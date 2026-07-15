#pragma once

#include "contract/registry/contract_registry.hpp"
#include "core/contract/contract_interface.hpp"
#include "core/errors/error.hpp"

namespace smo {

class KernelPingContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

class KernelWhoamiContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

class KernelSessionOpenContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

class KernelSessionCloseContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

class KernelDiscoverContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

class KernelNodeInfoContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

class KernelIdentityRotateContract : public Contract {
public:
    ContractID id() const override;
    ContractCategory category() const override { return ContractCategory::Kernel; }
    ContractABI abi() const override;
    Result<ExecutionResult> execute(
        const std::string& dag_json,
        const ExecutionContext& ctx) override;
};

Result<void> register_kernel_contracts(ContractRegistry& registry);

} // namespace smo
