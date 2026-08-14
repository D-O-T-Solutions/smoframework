#include <trust/trust.hpp>
#include <trust/witness.hpp>
#include <crypto/registry.hpp>
#include <providers/suite1_classical/suite1_classical_provider.hpp>
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>
#include <cmath>
#include <cstdio>
#include <cstring>

using namespace smo;

// ---------------------------------------------------------------------------
static int failures = 0;

#define TEST(name)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        printf("  TEST %-50s ... ", name);                                                                             \
        fflush(stdout);

#define END_TEST(result)                                                                                               \
    if (result)                                                                                                        \
    {                                                                                                                  \
        printf("PASS\n");                                                                                              \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        printf("FAIL\n");                                                                                              \
        ++failures;                                                                                                    \
    }                                                                                                                  \
    }                                                                                                                  \
    while (false)

#define ASSERT(cond)                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_EQ(a, b)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=%lld  RHS=%lld\n",                                                                       \
                   __FILE__, __LINE__, #a, #b, static_cast<long long>(a), static_cast<long long>(b));                  \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_NEAR(a, b, eps)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _diff_ = (a) - (b);                                                                                       \
        if (_diff_ < 0)                                                                                                \
            _diff_ = -_diff_;                                                                                          \
        if (_diff_ > (eps))                                                                                            \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: |%s - %s| < %g\n"                                                 \
                   "      diff=%g\n",                                                                                  \
                   __FILE__, __LINE__, #a, #b, (double)(eps), (double)_diff_);                                         \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

#define ASSERT_STREQ(a, b)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        const auto& _a = (a);                                                                                          \
        const auto& _b = (b);                                                                                          \
        if (_a != _b)                                                                                                  \
        {                                                                                                              \
            printf("\n    ASSERTION FAILED at %s:%d: %s == %s\n"                                                       \
                   "      LHS=\"%s\"  RHS=\"%s\"\n",                                                                   \
                   __FILE__, __LINE__, #a, #b, std::string(_a).c_str(), std::string(_b).c_str());                      \
            return false;                                                                                              \
        }                                                                                                              \
    } while (false)

// ==========================================================================
// Helper: make a NodeID with a given first byte
// ==========================================================================
static NodeID make_node_id(uint8_t first_byte)
{
    NodeID id;
    id.value.fill(0);
    id.value[0] = first_byte;
    return id;
}

// ==========================================================================
// Tests — TrustLevel
// ==========================================================================
static bool test_trust_level_to_string()
{
    ASSERT(std::strcmp(to_string(TrustLevel::None), "None") == 0);
    ASSERT(std::strcmp(to_string(TrustLevel::Low), "Low") == 0);
    ASSERT(std::strcmp(to_string(TrustLevel::Medium), "Medium") == 0);
    ASSERT(std::strcmp(to_string(TrustLevel::High), "High") == 0);
    ASSERT(std::strcmp(to_string(TrustLevel::Absolute), "Absolute") == 0);
    return true;
}

static bool test_compute_trust_level()
{
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.0)), 0);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.19)), 0);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.2)), 1);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.39)), 1);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.4)), 2);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.69)), 2);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.7)), 3);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.89)), 3);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(0.9)), 4);
    ASSERT_EQ(static_cast<int>(TrustManager::compute_trust_level(1.0)), 4);
    return true;
}

// ==========================================================================
// Tests — compute_composite
// ==========================================================================
static bool test_compute_composite_zero()
{
    TrustComponents c;
    ASSERT_NEAR(compute_composite(c), 0.0, 0.0001);
    return true;
}

static bool test_compute_composite_full()
{
    TrustComponents c{1.0, 1.0, 1.0, 1.0};
    ASSERT_NEAR(compute_composite(c), 1.0, 0.0001);
    return true;
}

static bool test_compute_composite_partial()
{
    TrustComponents c{0.5, 0.5, 0.5, 0.5};
    double expected = 0.5 * 0.2 + 0.5 * 0.5 + 0.5 * 0.2 + 0.5 * 0.1;
    ASSERT_NEAR(compute_composite(c), expected, 0.0001);
    return true;
}

static bool test_compute_composite_clamp()
{
    TrustComponents c{2.0, 2.0, 2.0, 2.0};
    ASSERT_NEAR(compute_composite(c), 1.0, 0.0001);
    return true;
}

// ==========================================================================
// Tests — TrustScore serialization
// ==========================================================================
static bool test_trust_score_roundtrip()
{
    TrustScore ts;
    ts.node_id = make_node_id(0xAA);
    ts.components.citizen = 0.8;
    ts.components.execution = 0.6;
    ts.components.witness = 0.4;
    ts.components.consistency = 0.2;
    ts.composite = compute_composite(ts.components);
    ts.last_updated = 12345;

    auto ser = ts.serialize();
    ASSERT(!ser.empty());

    auto deser = TrustScore::deserialize(ser);
    ASSERT(deser);
    ASSERT_EQ(deser.value().node_id.value[0], 0xAA);
    ASSERT_NEAR(deser.value().components.citizen, 0.8, 0.0001);
    ASSERT_NEAR(deser.value().components.execution, 0.6, 0.0001);
    ASSERT_NEAR(deser.value().components.witness, 0.4, 0.0001);
    ASSERT_NEAR(deser.value().components.consistency, 0.2, 0.0001);
    ASSERT_EQ(deser.value().last_updated, 12345);

    return true;
}

// ==========================================================================
// Tests — Attestation serialization
// ==========================================================================
static bool test_attestation_roundtrip()
{
    Attestation att;
    att.witness_id = make_node_id(0x01);
    att.subject_id = make_node_id(0x02);
    att.claimed_score = 0.75;
    att.timestamp = 5000;
    att.signature = {0xde, 0xad, 0xbe, 0xef};

    auto ser = att.serialize();
    ASSERT(!ser.empty());

    auto deser = Attestation::deserialize(ser);
    ASSERT(deser);
    ASSERT_EQ(deser.value().witness_id.value[0], 0x01);
    ASSERT_EQ(deser.value().subject_id.value[0], 0x02);
    ASSERT_NEAR(deser.value().claimed_score, 0.75, 0.0001);
    ASSERT_EQ(deser.value().timestamp, 5000);
    ASSERT_EQ(deser.value().signature.size(), 4U);

    return true;
}

// ==========================================================================
// Tests — TrustDigest serialization
// ==========================================================================
static bool test_trust_digest_roundtrip()
{
    TrustDigest d;
    d.origin = make_node_id(0xAA);
    d.sequence = 7;
    d.timestamp = 999;

    TrustScore ts;
    ts.node_id = make_node_id(0xBB);
    ts.composite = 0.85;
    d.scores.push_back(ts);

    auto ser = d.serialize();
    ASSERT(!ser.empty());

    auto deser = TrustDigest::deserialize(ser);
    ASSERT(deser);
    ASSERT_EQ(deser.value().origin.value[0], 0xAA);
    ASSERT_EQ(deser.value().sequence, 7);
    ASSERT_EQ(deser.value().timestamp, 999);
    ASSERT_EQ(deser.value().scores.size(), 1U);
    ASSERT_EQ(deser.value().scores[0].node_id.value[0], 0xBB);
    ASSERT_NEAR(deser.value().scores[0].composite, 0.85, 0.0001);

    return true;
}

// ==========================================================================
// Tests — TrustManager
// ==========================================================================
static bool test_trust_manager_record_success()
{
    TrustManager tm;
    NodeID n = make_node_id(0x01);

    tm.record_success(n, 1.0, 100);
    auto score = tm.get_score(n);
    ASSERT(score);
    ASSERT_NEAR(score.value(), 0.01 * 0.5, 0.0001); // execution +0.01 * 0.5

    return true;
}

static bool test_trust_manager_record_failure()
{
    TrustManager tm;
    NodeID n = make_node_id(0x01);

    tm.record_failure(n, 1.0, 100);
    auto score = tm.get_score(n);
    ASSERT(score);
    ASSERT_NEAR(score.value(), 0.0, 0.0001); // execution -0.02 → clamped to 0

    return true;
}

static bool test_trust_manager_record_offline()
{
    TrustManager tm;
    NodeID n = make_node_id(0x01);

    tm.record_offline(n, 100);
    auto score = tm.get_score(n);
    ASSERT(score);
    ASSERT_NEAR(score.value(), 0.0, 0.0001); // citizen -= 0.001 → 0

    // Set up a non-zero citizen via direct component access via success+time
    // To give citizen non-zero, we use a custom TrustManager that mocks it:
    // We'll verify penalty via the score delta after multiple offline records
    tm.record_success(n, 1.0, 200);
    tm.record_offline(n, 300); // citizen 0 - 0.001 = 0 (clamped)
    // After success: execution=0.01, composite=0.005
    // Offline on zero citizen: no change
    auto score2 = tm.get_score(n);
    ASSERT(score2);
    ASSERT_NEAR(score2.value(), 0.005, 0.0001);

    return true;
}

static bool test_trust_manager_get_score_not_found()
{
    TrustManager tm;
    auto score = tm.get_score(make_node_id(0xFF));
    ASSERT(!score);
    ASSERT_EQ(score.error().code.code, 200);

    return true;
}

static bool test_trust_manager_trust_anchor()
{
    TrustManager tm;
    NodeID n = make_node_id(0xAA);

    ASSERT(!tm.is_trust_anchor(n));

    TrustAnchor ta;
    ta.node_id = n;
    ta.public_key = {0x01, 0x02};
    ta.added_at = 100;
    tm.add_trust_anchor(ta);

    ASSERT(tm.is_trust_anchor(n));

    // Trust anchor should get default 1.0 score
    auto score = tm.get_score(n);
    ASSERT(score);
    ASSERT_NEAR(score.value(), 1.0, 0.0001);

    // Remove
    ASSERT(tm.remove_trust_anchor(n));
    ASSERT(!tm.is_trust_anchor(n));

    return true;
}

static bool test_trust_manager_all_scores()
{
    TrustManager tm;
    tm.record_success(make_node_id(0x01), 1.0, 100);
    tm.record_success(make_node_id(0x02), 1.0, 200);
    ASSERT_EQ(tm.all_scores().size(), 2U);
    ASSERT_EQ(tm.count(), 2U);

    return true;
}

static bool test_trust_manager_verify_attestation()
{
    // Initialize all crypto suites via registry
    auto& reg = CryptoRegistry::instance();
    
    // Test with all registered suites
    for (auto suite_id : reg.available_suites())
    {
        auto crypto_res = reg.get_suite(suite_id);
        if (!crypto_res) continue;
        const auto* crypto = crypto_res.value();
        
        TrustManager tm;
        
        // Create a witness anchor with a keypair from this suite
        auto rng = crypto->default_rng();
        auto kp_res = crypto->signer.generate_keypair(rng);
        if (!kp_res) continue;
        auto kp = std::move(kp_res).value();
        
        // Add witness as trust anchor
        TrustAnchor anchor;
        anchor.node_id = make_node_id(0x01);
        anchor.public_key = std::move(kp.public_key);
        tm.add_trust_anchor(std::move(anchor));
        
        // Create valid attestation signed by the witness key
        Attestation att;
        att.witness_id = make_node_id(0x01);
        att.subject_id = make_node_id(0x02);
        att.claimed_score = 0.5;
        att.timestamp = 1000;
        
        // Sign canonical payload
        Attestation payload_att;
        payload_att.witness_id = att.witness_id;
        payload_att.subject_id = att.subject_id;
        payload_att.claimed_score = att.claimed_score;
        payload_att.timestamp = att.timestamp;
        payload_att.signature.clear();
        auto payload = payload_att.serialize();
        
        auto sig_res = crypto->signer.sign(BytesView(payload), BytesView(kp.secret_key), rng);
        if (!sig_res) continue;
        att.signature = std::move(sig_res).value();
        
        // Valid attestation should pass
        auto verify_res = tm.verify_attestation(att, 1500, 10000, crypto);
        if (!verify_res) return false;
        
        // Missing timestamp
        Attestation bad1 = att;
        bad1.timestamp = 0;
        auto bad1_res = tm.verify_attestation(bad1, 1500, 10000, crypto);
        if (bad1_res) return false;
        
        // Expired
        Attestation bad2 = att;
        auto bad2_res = tm.verify_attestation(bad2, 9999999999999LL, 1000, crypto);
        if (bad2_res) return false;
        
        // Score out of range
        Attestation bad3 = att;
        bad3.claimed_score = 1.5;
        auto bad3_res = tm.verify_attestation(bad3, 1500, 10000, crypto);
        if (bad3_res) return false;
        
        // Missing signature
        Attestation bad4 = att;
        bad4.signature.clear();
        auto bad4_res = tm.verify_attestation(bad4, 1500, 10000, crypto);
        if (bad4_res) return false;
    }
    
    return true;
}

static bool test_trust_manager_apply_attestation()
{
    TrustManager tm;
    NodeID subject = make_node_id(0xAA);

    // Initial score
    tm.record_success(subject, 1.0, 100);

    Attestation att;
    att.witness_id = make_node_id(0x01);
    att.subject_id = subject;
    att.claimed_score = 0.9;
    att.timestamp = 200;
    att.signature = {0x01};

    tm.apply_attestation(att);

    auto score = tm.get_score(subject);
    ASSERT(score);
    // execution = 0.01, witness = (0 * 0.7) + (0.9 * 0.3) = 0.27
    // composite = 0.01*0.5 + 0.27*0.2 = 0.005 + 0.054 = 0.059
    double expected = 0.01 * 0.5 + 0.27 * 0.2;
    ASSERT_NEAR(score.value(), expected, 0.0001);

    return true;
}

static bool test_trust_manager_produce_and_apply_digest()
{
    TrustManager tm1;
    NodeID n1 = make_node_id(0x01);
    NodeID n2 = make_node_id(0x02);

    tm1.record_success(n1, 1.0, 100);
    tm1.record_success(n2, 2.0, 200);

    auto digest = tm1.produce_digest(make_node_id(0xFF), 300);
    ASSERT_EQ(digest.scores.size(), 2U);
    ASSERT_EQ(digest.sequence, 1);

    // Apply to a fresh TrustManager (no crypto provider, signature empty so skip verify)
    TrustManager tm2;
    ASSERT(tm2.apply_digest(digest, nullptr));
    ASSERT_EQ(tm2.count(), 2U);

    auto s1 = tm2.get_score(n1);
    auto s2 = tm2.get_score(n2);
    ASSERT(s1);
    ASSERT(s2);

    return true;
}

static bool test_trust_manager_apply_empty_digest()
{
    TrustManager tm;
    TrustDigest d;
    d.origin = make_node_id(0xFF);
    d.scores = {};
    ASSERT(!tm.apply_digest(d, nullptr));

    return true;
}

static bool test_trust_manager_tick_decay()
{
    TrustManager tm;
    NodeID n = make_node_id(0x01);

    tm.record_success(n, 100.0, 1);
    auto before = tm.get_score(n);
    ASSERT(before);

    // Tick after 1 day
    tm.tick(86400000000000LL + 1);
    auto after = tm.get_score(n);
    ASSERT(after);

    // Score should have decayed (half-life = 30 days → factor ~0.977)
    double factor = std::pow(0.5, 1.0 / 30.0);
    ASSERT_NEAR(after.value(), before.value() * factor, 0.001);

    return true;
}

static bool test_trust_manager_serialization()
{
    TrustManager tm1;
    NodeID n1 = make_node_id(0x01);

    tm1.record_success(n1, 1.0, 100);

    TrustAnchor ta;
    ta.node_id = make_node_id(0xAA);
    ta.public_key = {0xca, 0xfe};
    ta.added_at = 500;
    tm1.add_trust_anchor(ta);

    auto ser = tm1.serialize();
    ASSERT(!ser.empty());

    auto tm2 = TrustManager::deserialize(ser);
    ASSERT(tm2);
    ASSERT_EQ(tm2.value().count(), 1U);
    ASSERT(tm2.value().is_trust_anchor(make_node_id(0xAA)));

    auto score = tm2.value().get_score(n1);
    ASSERT(score);

    return true;
}

static bool test_trust_manager_config()
{
    TrustConfig cfg;
    cfg.weight_citizen = 0.5;
    cfg.weight_execution = 0.3;
    cfg.weight_witness = 0.1;
    cfg.weight_consistency = 0.1;

    TrustManager tm(cfg);
    ASSERT_NEAR(tm.config().weight_citizen, 0.5, 0.0001);

    return true;
}

// ==========================================================================
// WitnessSelector (RFC 0003)
// ==========================================================================

static bool test_witness_selector_excludes_participants()
{
    smo::trust::WitnessSelector sel;
    NodeID a, b, c;
    a.value.fill(0x01);
    b.value.fill(0x02);
    c.value.fill(0x03);

    std::vector<smo::trust::WitnessSelector::Candidate> candidates;
    candidates.push_back({a, true, 0.8, false});
    candidates.push_back({b, true, 0.9, false});
    candidates.push_back({c, true, 0.7, false});

    // Requester = a, responder = b → only c remains eligible.
    auto witness = sel.select(a, b, candidates);
    ASSERT(witness);
    if (witness.value() != c)
    {
        printf("    unexpected witness selected\n");
        return false;
    }

    return true;
}

static bool test_witness_selector_prefers_online_high_trust()
{
    smo::trust::WitnessSelector sel;
    NodeID r, resp, best_offline, best_online, anchor;
    r.value.fill(0x10);
    resp.value.fill(0x20);
    best_offline.value.fill(0x30);
    best_online.value.fill(0x40);
    anchor.value.fill(0x50);

    std::vector<smo::trust::WitnessSelector::Candidate> candidates;
    // Higher trust but offline / not anchor.
    candidates.push_back({best_offline, false, 0.95, false});
    // Slightly lower trust but online.
    candidates.push_back({best_online, true, 0.9, false});
    // Anchor is never a witness, even with max trust.
    candidates.push_back({anchor, true, 1.0, true});

    auto witness = sel.select(r, resp, candidates);
    ASSERT(witness);
    if (witness.value() != best_online)
    {
        printf("    expected online candidate selected\n");
        return false;
    }

    return true;
}

static bool test_witness_selector_fallback_local()
{
    smo::trust::WitnessSelector sel;
    NodeID a, b;
    a.value.fill(0xA1);
    b.value.fill(0xB2);

    std::vector<smo::trust::WitnessSelector::Candidate> candidates;
    candidates.push_back({a, true, 0.8, false});
    candidates.push_back({b, true, 0.9, false});

    // No third party → no witness → local decision (RFC 0003 §3.4).
    auto witness = sel.select(a, b, candidates);
    ASSERT(!witness);

    return true;
}

// ==========================================================================
// Main
// ==========================================================================

int main(int, char*[])
{
    printf("SMO Trust — Unit Tests\n");
    printf("======================\n\n");

    TEST("TrustLevel to_string") END_TEST(test_trust_level_to_string());
    TEST("compute_trust_level") END_TEST(test_compute_trust_level());
    TEST("compute_composite zero") END_TEST(test_compute_composite_zero());
    TEST("compute_composite full") END_TEST(test_compute_composite_full());
    TEST("compute_composite partial") END_TEST(test_compute_composite_partial());
    TEST("compute_composite clamp") END_TEST(test_compute_composite_clamp());
    TEST("TrustScore roundtrip") END_TEST(test_trust_score_roundtrip());
    TEST("Attestation roundtrip") END_TEST(test_attestation_roundtrip());
    TEST("TrustDigest roundtrip") END_TEST(test_trust_digest_roundtrip());
    TEST("TM record_success") END_TEST(test_trust_manager_record_success());
    TEST("TM record_failure") END_TEST(test_trust_manager_record_failure());
    TEST("TM record_offline") END_TEST(test_trust_manager_record_offline());
    TEST("TM get_score not found") END_TEST(test_trust_manager_get_score_not_found());
    TEST("TM trust anchor") END_TEST(test_trust_manager_trust_anchor());
    TEST("TM all_scores") END_TEST(test_trust_manager_all_scores());
    TEST("TM verify_attestation") END_TEST(test_trust_manager_verify_attestation());
    TEST("TM apply_attestation") END_TEST(test_trust_manager_apply_attestation());
    TEST("TM produce and apply digest") END_TEST(test_trust_manager_produce_and_apply_digest());
    TEST("TM apply empty digest") END_TEST(test_trust_manager_apply_empty_digest());
    TEST("TM tick decay") END_TEST(test_trust_manager_tick_decay());
    TEST("TM serialization") END_TEST(test_trust_manager_serialization());
    TEST("TM config") END_TEST(test_trust_manager_config());
    TEST("WS excludes requester+responder") END_TEST(test_witness_selector_excludes_participants());
    TEST("WS prefers online high trust, no anchor") END_TEST(test_witness_selector_prefers_online_high_trust());
    TEST("WS fallback local when no third party") END_TEST(test_witness_selector_fallback_local());

    printf("\n");
    if (failures == 0)
    {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    else
    {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}
