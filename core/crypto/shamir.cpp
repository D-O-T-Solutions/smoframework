#include "shamir.hpp"

#include "core/crypto/random/getrandom.hpp"
#include "core/crypto/secure/zeroize.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace smo {
    namespace crypto {
        namespace shamir_detail {

            // GF(256) multiplication with polynomial x^8 + x^4 + x^3 + x + 1 (0x11D)
            uint8_t gf_mul(uint8_t a, uint8_t b) noexcept
            {
                uint16_t result = 0;
                for (int i = 0; i < 8; ++i)
                {
                    if (b & 1)
                        result ^= a;
                    bool high_bit = (a & 0x80) != 0;
                    a <<= 1;
                    if (high_bit)
                        a ^= 0x1D; // x^4 + x^3 + x + 1 (without x^8 since we shifted)
                    b >>= 1;
                }
                return static_cast<uint8_t>(result);
            }

            uint8_t gf_add(uint8_t a, uint8_t b) noexcept
            {
                return a ^ b; // Addition in GF(2^8) is XOR
            }

            uint8_t gf_pow(uint8_t a, int n) noexcept
            {
                uint8_t result = 1;
                while (n > 0)
                {
                    if (n & 1)
                        result = gf_mul(result, a);
                    a = gf_mul(a, a);
                    n >>= 1;
                }
                return result;
            }

            uint8_t gf_inv(uint8_t a) noexcept
            {
                // a^(254) = a^(-1) in GF(256) since 255 is the order of the multiplicative group
                return gf_pow(a, 254);
            }

            uint8_t gf_div(uint8_t a, uint8_t b) noexcept
            {
                return gf_mul(a, gf_inv(b));
            }

        } // namespace shamir_detail

        Result<Bytes> ShamirShare::serialize() const
        {
            if (y.size() != 32)
                return SMO_ERR_CRYPTO(160, Error, NoRetry, ManualIntervention, "ShamirShare: y-coordinate must be 32 bytes");

            Bytes out(33);
            out[0] = index;
            std::memcpy(out.data() + 1, y.data(), 32);
            return out;
        }

        Result<ShamirShare> ShamirShare::deserialize(BytesView data)
        {
            if (data.size() != 33)
                return SMO_ERR_CRYPTO(161, Error, NoRetry, ManualIntervention, "ShamirShare: expected 33 bytes");

            ShamirShare share;
            share.index = data[0];
            share.y.assign(data.data() + 1, data.data() + 33);
            if (share.index == 0)
                return SMO_ERR_CRYPTO(162, Error, NoRetry, ManualIntervention, "ShamirShare: index cannot be 0");
            return share;
        }

        Result<std::vector<ShamirShare>> shamir_split(BytesView secret, uint8_t N, uint8_t M, RngRef& rng)
        {
            if (secret.size() != 32)
                return SMO_ERR_CRYPTO(163, Error, NoRetry, ManualIntervention, "shamir_split: secret must be 32 bytes");
            if (M == 0 || M > N)
                return SMO_ERR_CRYPTO(164, Error, NoRetry, ManualIntervention, "shamir_split: invalid threshold (1 <= M <= N)");
            if (N > 255)
                return SMO_ERR_CRYPTO(165, Error, NoRetry, ManualIntervention, "shamir_split: N cannot exceed 255");

            // Pre-create all shares upfront to avoid reallocation issues
            std::vector<ShamirShare> shares;
            shares.reserve(N);
            for (uint8_t x = 1; x <= N; ++x)
            {
                ShamirShare s;
                s.index = x;
                s.y.resize(32, 0);
                shares.push_back(std::move(s));
            }

            // For each byte position in the 32-byte secret, generate a polynomial
            // of degree M-1 with that byte as the constant term.
            for (size_t byte_pos = 0; byte_pos < 32; ++byte_pos)
            {
                uint8_t secret_byte = secret[byte_pos];

                // Generate random coefficients for degree M-1 polynomial
                // coeffs[0] = secret_byte (constant term)
                // coeffs[1..M-1] = random
                Bytes coeffs(M);
                coeffs[0] = secret_byte;
                if (M > 1)
                {
                    Bytes random_coeffs(M - 1);
                    rng.fill(BytesMutView{random_coeffs.data(), random_coeffs.size()});
                    std::memcpy(coeffs.data() + 1, random_coeffs.data(), M - 1);
                }

                // Evaluate polynomial at x = 1..N
                for (uint8_t x = 1; x <= N; ++x)
                {
                    // Evaluate: y = sum_{i=0}^{M-1} coeffs[i] * x^i
                    uint8_t y = 0;
                    uint8_t x_pow = 1; // x^0
                    for (size_t i = 0; i < M; ++i)
                    {
                        y = shamir_detail::gf_add(y, shamir_detail::gf_mul(coeffs[i], x_pow));
                        x_pow = shamir_detail::gf_mul(x_pow, x);
                    }
                    shares[x - 1].y[byte_pos] = y;
                }

                secure::zeroize(coeffs.data(), coeffs.size());
            }

            return shares;
        }

        Result<Bytes> shamir_recover(const std::vector<ShamirShare>& shares, uint8_t M)
        {
            if (shares.size() < M)
                return SMO_ERR_CRYPTO(166, Error, NoRetry, ManualIntervention, "shamir_recover: insufficient shares (need at least M)");
            if (M == 0)
                return SMO_ERR_CRYPTO(167, Error, NoRetry, ManualIntervention, "shamir_recover: threshold M must be >= 1");
            if (shares.size() > 255)
                return SMO_ERR_CRYPTO(168, Error, NoRetry, ManualIntervention, "shamir_recover: too many shares");

            // Verify all shares have 32-byte y-coordinates
            for (const auto& s : shares)
            {
                if (s.y.size() != 32)
                    return SMO_ERR_CRYPTO(169, Error, NoRetry, ManualIntervention, "shamir_recover: share y-coordinate must be 32 bytes");
                if (s.index == 0)
                    return SMO_ERR_CRYPTO(170, Error, NoRetry, ManualIntervention, "shamir_recover: share index cannot be 0");
            }

            // Check for duplicate indices
            for (size_t i = 0; i < shares.size(); ++i)
            {
                for (size_t j = i + 1; j < shares.size(); ++j)
                {
                    if (shares[i].index == shares[j].index)
                        return SMO_ERR_CRYPTO(171, Error, NoRetry, ManualIntervention, "shamir_recover: duplicate share indices");
                }
            }

            // Use Lagrange interpolation to recover the constant term (secret byte)
            // for each of the 32 byte positions.
            Bytes secret(32, 0);

            for (size_t byte_pos = 0; byte_pos < 32; ++byte_pos)
            {
                uint8_t secret_byte = 0;

                // Lagrange basis: secret = sum_{i} y_i * l_i(0)
                // where l_i(0) = product_{j != i} (x_j / (x_j - x_i))
                for (size_t i = 0; i < M; ++i)
                {
                    uint8_t y_i = shares[i].y[byte_pos];
                    uint8_t x_i = shares[i].index;

                    // Compute l_i(0) = product_{j != i} (x_j * (x_j - x_i)^(-1))
                    uint8_t lagrange_coeff = 1;
                    for (size_t j = 0; j < M; ++j)
                    {
                        if (i == j)
                            continue;
                        uint8_t x_j = shares[j].index;
                        uint8_t diff = shamir_detail::gf_add(x_j, x_i); // x_j - x_i = x_j + x_i in GF(2^8)
                        uint8_t term = shamir_detail::gf_div(x_j, diff);
                        lagrange_coeff = shamir_detail::gf_mul(lagrange_coeff, term);
                    }

                    secret_byte = shamir_detail::gf_add(secret_byte, shamir_detail::gf_mul(y_i, lagrange_coeff));
                }

                secret[byte_pos] = secret_byte;
            }

            return secret;
        }

    } // namespace crypto
} // namespace smo