# ── Consensus module — Raft log + future replication engine
target_sources(smo_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/raft_log.cpp
)
target_sources(smo_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/raft_log.hpp
)