# ZKMTD 코드 작동방식 (하이레벨 아키텍처)

포스트-양자 영지식 증명(ZKP) + Moving Target Defense(MTD) 라이브러리의 내부 동작을 모듈별로 상세히 설명합니다.

---

## 목차

1. [전체 아키텍처 개요](#1-전체-아키텍처-개요)
2. [모듈 구조](#2-모듈-구조)
3. [Core 모듈 — 타입, 트레이트, 에러](#3-core-모듈--타입-트레이트-에러)
4. [STARK 모듈 — 증명 시스템](#4-stark-모듈--증명-시스템)
5. [MTD 모듈 — 시간 기반 방어](#5-mtd-모듈--시간-기반-방어)
6. [Batching 모듈 — 배치 처리와 Merkle Tree](#6-batching-모듈--배치-처리와-merkle-tree)
7. [Utils 모듈 — 해시, 압축, 상수](#7-utils-모듈--해시-압축-상수)
8. [Solana 모듈 — 온체인 경량 검증](#8-solana-모듈--온체인-경량-검증)
9. [전체 데이터 흐름](#9-전체-데이터-흐름)
10. [Committed Public Inputs — 프라이버시 (Privacy-by-Default)](#10-committed-public-inputs--프라이버시-privacy-by-default)
11. [보안 설계](#11-보안-설계)
12. [테스트 구조](#12-테스트-구조)

---

## 1. 전체 아키텍처 개요

ZKMTD는 네 가지 핵심 문제를 해결합니다:

| 문제 | 해결 방법 | 관련 모듈 |
|------|----------|----------|
| 양자 컴퓨터 내성 | 해시 기반 STARK (타원곡선 미사용) | `stark/` |
| 증명 재사용(Replay) 방지 | 시간 기반 epoch 파라미터 자동 교체 | `mtd/` |
| 블록체인 검증 비용 | 경량 커밋먼트 검증 (~15K CU) | `solana/` |
| 대량 증명 처리 | Merkle tree 기반 배치 집계 | `batching/` |

```
┌──────────────────────────────────────────────────────────────────┐
│                         ZKMTD Library                            │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌────────────────┐   │
│  │  core/   │  │  stark/  │  │   mtd/    │  │   batching/    │   │
│  │          │  │          │  │           │  │                │   │
│  │ - types  │  │ - prover │  │ - epoch   │  │ - aggregator   │   │
│  │ - traits │  │ - verify │  │ - warping │  │ - merkle       │   │
│  │ - errors │  │ - AIR    │  │ - manager │  │ - batch_verify │   │
│  │          │  │ - config │  │ - entropy │  │                │   │
│  └──────────┘  └──────────┘  └───────────┘  └────────────────┘   │
│                                                                  │
│  ┌──────────┐  ┌────────────────────────────────────────────┐    │
│  │  utils/  │  │  solana/ (feature-gated)                   │    │
│  │          │  │  - lightweight proof                       │    │
│  │ - hash   │  │  - onchain verifier                        │    │
│  │ - const  │  └────────────────────────────────────────────┘    │
│  │ - compr  │                                                    │
│  └──────────┘                                                    │
└──────────────────────────────────────────────────────────────────┘
```

라이브러리 진입점은 `src/lib.rs`이며, 각 모듈을 re-export합니다.


## 2. 모듈 구조

```
src/
├── lib.rs                 # 진입점, prelude, re-exports
├── core/
│   ├── types.rs           # Proof, Witness, PublicInputs, ProofBatch
│   ├── traits.rs          # Prover, Verifier, EntropySource, BatchProver
│   └── errors.rs          # ZKMTDError (15개 에러 variant)
├── stark/
│   ├── mod.rs             # 3개 구현체 export (Simulation / Real / Integrated)
│   ├── config.rs          # StarkConfig + Builder 패턴
│   ├── air.rs             # AIR 회로 (Fibonacci, Sum, Multiplication)
│   ├── range_air.rs       # Range Proof AIR (value >= threshold)
│   ├── prover.rs          # MTDProver / MTDVerifier (시뮬레이션 레이어)
│   ├── verifier.rs        # MTDVerifier의 Verifier trait 구현
│   ├── real_stark.rs      # RealStarkProver / RealStarkVerifier (Plonky3 STARK)
│   └── integrated.rs      # IntegratedProver / IntegratedVerifier (STARK + MTD)
├── mtd/
│   ├── mod.rs             # 모듈 export
│   ├── epoch.rs           # Epoch 타입 (시간 → epoch 변환)
│   ├── warping.rs         # WarpingParams (epoch별 암호 파라미터)
│   ├── manager.rs         # MTDManager (epoch 전환, 캐싱)
│   └── entropy.rs         # SystemEntropy, SolanaEntropy
├── batching/
│   ├── mod.rs             # 모듈 export
│   ├── aggregator.rs      # BatchProver, create_proof_batch()
│   ├── batch_verifier.rs  # BatchVerifier (Merkle root + 개별 검증)
│   └── merkle.rs          # MerkleTree, MerklePath
├── utils/
│   ├── constants.rs       # 50+ 프로토콜 상수
│   ├── hash.rs            # Poseidon2 해시 (Goldilocks 필드)
│   └── compression.rs     # RLE 압축, 체크섬 검증
├── solana/                # (feature-gated: solana-program)
│   ├── lightweight.rs     # LightweightProof
│   └── onchain_verifier.rs # OnchainVerifier
└── adapters/
    └── solana.rs          # Solana 어댑터
```

---

## 3. Core 모듈 — 타입, 트레이트, 에러

### 3.1 핵심 타입 (`core/types.rs`)

#### `Proof`
증명 결과물입니다. 증명 데이터(`data: Vec<u8>`), 생성 시점의 epoch, 프로토콜 버전을 담습니다.

```rust
pub struct Proof {
    pub data: Vec<u8>,   // 증명 바이트 데이터
    pub epoch: u64,      // 이 증명이 생성된 epoch
    pub version: u8,     // 프로토콜 버전 (현재 1)
}
```

#### `Witness`
비밀 입력 데이터입니다. **`ZeroizeOnDrop`을 구현**하여 스코프를 벗어나면 메모리에서 자동 소거됩니다. `Debug` 출력 시 `<redacted>`로 표시되어 로그에 비밀이 노출되지 않습니다.

```rust
pub struct Witness {
    pub data: Vec<u64>,  // 비밀 필드 원소들
}
// Drop 시 data가 모두 0으로 덮어씌워짐
```

#### `PublicInputs`
공개 입력입니다. 증명자와 검증자가 동일한 값을 공유합니다.

#### `ProofBatch`
여러 증명을 Merkle root와 함께 묶은 배치입니다.

```rust
pub struct ProofBatch {
    pub proofs: Vec<Proof>,
    pub merkle_root: [u8; 32],  // 전체 배치의 Merkle root
    pub epoch: u64,
}
```

### 3.2 트레이트 (`core/traits.rs`)

시스템의 핵심 인터페이스를 정의합니다:

| 트레이트 | 역할 | 핵심 메서드 |
|---------|------|-----------|
| `Prover` | 증명 생성 | `prove(witness, public_inputs) -> Proof` |
| `Verifier` | 증명 검증 | `verify(proof, public_inputs) -> bool` |
| `EntropySource` | 암호학적 랜덤 제공 | `fill_bytes(output)`, `entropy_bits()` |
| `BatchProver` | 배치 증명 생성 | `prove_batch(witnesses, inputs) -> Vec<Proof>` |

### 3.3 에러 (`core/errors.rs`)

`ZKMTDError` enum에 15개 에러 variant가 정의되어 있습니다. `std`/`no_std` 모두 지원하며, `alloc` feature 여부에 따라 에러 메시지가 동적(`String`) 또는 정적(`&'static str`)으로 결정됩니다.

주요 에러:
- `ProofGenerationFailed` — 증명 생성 실패
- `VerificationFailed` — 검증 실패
- `InvalidEpoch { current, reason }` — epoch 불일치
- `MTDError` — MTD 파라미터 관련 오류
- `MerkleError` — Merkle tree 오류

---

## 4. STARK 모듈 — 증명 시스템

### 4.1 세 가지 구현 레벨

STARK 모듈은 세 개의 구현체를 제공하며, 용도에 따라 선택합니다:

```
┌─────────────────────────────────────────────────────────┐
│  Level 1: MTDProver  MTDVerifier (시뮬레이션, deprecated)    │
│  - 해시 기반 시뮬레이션 (테스트/프로토타입용)                     │
│  - 파일: prover.rs, verifier.rs                          │
├─────────────────────────────────────────────────────────┤
│  Level 2: RealStarkProver / RealStarkVerifier           │
│  - Plonky3 기반 실제 STARK 증명                            │
│  - feature: full-p3                                     │
│  - 파일: real_stark.rs                                   │
├─────────────────────────────────────────────────────────┤
│  Level 3: IntegratedProver / IntegratedVerifier (권장)   │
│  - Real STARK + MTD 바인딩 결합                            │
│  - feature: full-p3                                     │
│  - 파일: integrated.rs                                   │
└─────────────────────────────────────────────────────────┘
```

### 4.2 시뮬레이션 레이어 (`prover.rs`, `verifier.rs`)

`MTDProver`의 `prove()` 호출 시 내부에서 일어나는 일:

```
MTDProver::prove(witness, public_inputs)
    │
    ├─ 1. witness 크기 검증 (최소 4개 원소)
    │
    ├─ 2. commit_trace(witness_data, params)
    │      └─ witness + domain_separator를 Poseidon2로 해시
    │      └─ → trace_commitment: [u8; 32]
    │
    ├─ 3. generate_fri_proof(witness_data, params)
    │      └─ fri_seed + salt 기반 쿼리 응답 시뮬레이션
    │      └─ → fri_proof: Vec<u8>
    │
    ├─ 4. 직렬화: trace_commitment ∥ fri_proof ∥ public_inputs
    │
    └─ 5. integrity_hash = Poseidon2(전체 데이터, "PROOF_INTEGRITY")
           └─ → Proof { data, epoch, version: 1 }
```

`MTDVerifier`의 `verify()` 호출 시:

```
MTDVerifier::verify(proof, public_inputs)
    │
    ├─ 1. epoch 일치 확인 (proof.epoch == verifier.current_epoch)
    ├─ 2. 최소 크기 확인 (64 bytes)
    │
    └─ verify_internal()
        ├─ verify_integrity_hash()
        │   └─ proof 끝 32바이트가 나머지 데이터의 Poseidon2 해시와 일치하는지 검증
        │   └─ constant_time_eq()로 타이밍 공격 방지
        │
        ├─ verify_fri_proof()
        │   └─ fri_seed가 현재 epoch의 WarpingParams.fri_seed와 일치하는지
        │   └─ query 응답이 WarpingParams.salt와 일치하는지
        │   └─ trace_commitment + fri_seed의 바인딩 해시 계산
        │
        ├─ verify_public_inputs()
        │   └─ proof 내 직렬화된 public_inputs가 제공된 값과 일치하는지
        │
        └─ verify_params_consistency()
            └─ trace_commitment가 0이 아닌지
            └─ domain_separator가 0이 아닌지
            └─ trace + domain_separator 바인딩 해시 유효성
```

### 4.3 실제 Plonky3 STARK (`real_stark.rs`)

`full-p3` feature 활성화 시 사용 가능합니다. Plonky3의 `p3_uni_stark::prove/verify`를 직접 호출합니다.

**타입 체인:**
```
Val = Goldilocks (2^64 - 2^32 + 1 소수체)
Challenge = BinomialExtensionField<Goldilocks, 2>
Perm = Poseidon2<Goldilocks, width=16, degree=7>
Hash = PaddingFreeSponge<Perm, 16, 8, 8>
Compress = TruncatedPermutation<Perm, 2, 8, 16>
ValMmcs = FieldMerkleTreeMmcs
Pcs = TwoAdicFriPcs (Polynomial Commitment Scheme)
```

**증명 과정 (`prove_fibonacci`):**

```
RealStarkProver::prove_fibonacci(num_rows)
    │
    ├─ 1. 실행 트레이스 생성
    │      └─ Fibonacci 수열: F(0)=0, F(1)=1, F(n+2)=F(n)+F(n+1)
    │      └─ RowMajorMatrix<Goldilocks> (width=2, height=num_rows)
    │
    ├─ 2. Public values 계산: [F(0), F(1), F(last-1), F(last)]
    │
    ├─ 3. STARK 설정 구성
    │      ├─ FriConfig: log_blowup=2, queries=60, pow_bits=8
    │      ├─ Merkle tree commitment scheme 생성
    │      └─ PCS (Polynomial Commitment) 생성
    │
    ├─ 4. DuplexChallenger 생성 (Fiat-Shamir 변환)
    │
    └─ 5. p3_uni_stark::prove() 호출
           └─ → RealProof { inner: Proof<MyStarkConfig>, public_values, ... }
```

**검증 과정 (`verify_fibonacci`):**

```
RealStarkVerifier::verify_fibonacci(proof)
    │
    ├─ 1. Public values 무결성 검증
    │      └─ Fibonacci 수열 직접 재계산하여 대조
    │
    ├─ 2. 동일한 STARK config + challenger 재구성
    │
    └─ 3. p3_uni_stark::verify() 호출
           └─ FRI 검증, 다항식 커밋먼트 검증
```

**추가 지원 회로:**

`RealStarkProver`는 Fibonacci 외에 세 가지 회로를 추가로 지원합니다:

- `prove_sum(a, b)` / `verify_sum(proof)` — 덧셈 회로 (width=3, `c = a + b`)
- `prove_multiplication(a, b)` / `verify_multiplication(proof)` — 곱셈 회로 (width=3, `c = a * b`)
- `prove_range(value, threshold)` / `verify_range(proof)` — 범위 증명 (width=35, 32-bit 분해)

각 증명은 `ProofAirType` enum으로 AIR 타입을 기록하며, `verify_by_type()` 메서드로 자동 분기합니다.

### 4.4 통합 레이어 (`integrated.rs`) — **프로덕션 권장**

`IntegratedProver`는 Real STARK 증명에 MTD 바인딩을 결합합니다:

```
IntegratedProver::prove_fibonacci(num_rows, pv_salt)
    │
    ├─ 1. RealStarkProver.prove_fibonacci(num_rows)
    │      └─ 실제 STARK 증명 생성
    │
    ├─ 2. 현재 epoch & WarpingParams 취득
    │
    ├─ 3. committed_hash 계산
    │      └─ CommittedPublicInputs::commit(public_values, pv_salt)
    │      └─ Poseidon2(public_values ∥ pv_salt, "ZKMTD::PV::Commit")
    │
    └─ 4. binding_hash 계산
           └─ Poseidon2(public_values ∥ committed_hash ∥ value_count
                        ∥ epoch ∥ domain_separator ∥ fri_seed ∥ salt,
                        "ZKMTD_BINDING")
           └─ → IntegratedProof { stark_proof, epoch, params, binding_hash,
                                  committed_public_values, pv_salt }
```

`IntegratedVerifier::verify()`:

```
IntegratedVerifier::verify(proof)
    │
    ├─ 1. proof.epoch == verifier.current_epoch 확인
    ├─ 2. proof.params == verifier.current_params 확인
    │      (domain_separator, fri_seed, salt 모두 일치)
    ├─ 3. binding_hash 재계산 후 대조
    │      compute_binding_hash() (단일 구현, 중복 없음)
    │      (public_values ∥ commitment ∥ value_count ∥ epoch ∥ ...,
    │       "ZKMTD_BINDING")
    └─ 4. RealStarkVerifier.verify_by_type() (STARK 검증, AIR 타입별 분기)
```

**핵심**: epoch이 다르거나, seed가 다르거나, binding_hash가 변조되면 검증 실패합니다.

### 4.5 AIR 회로 (`air.rs`, `range_air.rs`)

**AIR** (Algebraic Intermediate Representation)은 "올바른 계산"의 제약 조건을 다항식으로 표현합니다.

#### SimpleAir — 3가지 회로

| 타입 | 컬럼 | 제약 조건 | 차수 |
|------|------|----------|------|
| Fibonacci | 2 | `next[0] = local[1]`, `next[1] = local[0] + local[1]` | 1 |
| Sum | 3 | `local[2] = local[0] + local[1]` | 1 |
| Multiplication | 3 | `local[2] = local[0] * local[1]` | 2 |

Plonky3의 `Air<AirBuilder>` 트레이트를 구현하여 `builder.when_transition().assert_eq(...)` 형태로 제약을 선언합니다.

#### RangeAir — 범위 증명

값이 threshold 이상인지 **실제 값을 공개하지 않고** 증명합니다.

```
컬럼 구조: [bit_0, bit_1, ..., bit_31, value, threshold, diff]
                                         (총 35 컬럼)

제약 조건:
1. 각 bit는 이진값: bit * (1 - bit) = 0
2. diff = value - threshold
3. 비트 분해: sum(bit_i * 2^i) = diff
```

`diff`가 비트로 분해 가능하다면 diff >= 0, 즉 value >= threshold임이 보장됩니다.

### 4.6 StarkConfig (`config.rs`)

STARK 증명 시스템의 암호학적 파라미터를 설정합니다:

```rust
pub struct StarkConfig {
    pub security_bits: usize,      // 80~256
    pub fri_folding_factor: usize, // 2, 4, 8, 16
    pub fri_queries: usize,        // 20~500
    pub grinding_bits: usize,      // 0~30
    pub blowup_factor: usize,      // 2, 4, 8, 16
    pub trace_height: usize,       // 64~8192 (2의 거듭제곱)
}
```

프리셋:
- `StarkConfig::for_testing()` — 80-bit 보안, 빠른 실행
- `StarkConfig::default()` — 100-bit 보안, 일반 용도
- `StarkConfig::high_security()` — 128-bit 보안, 프로덕션

Builder 패턴으로 커스텀 설정도 가능합니다:
```rust
StarkConfig::builder()
    .security_bits(128)
    .fri_queries(150)
    .build()?;
```

`validate()`에서 모든 파라미터의 범위/정합성을 검사합니다.

---

## 5. MTD 모듈 — 시간 기반 방어

MTD(Moving Target Defense)는 증명의 시간적 유효성을 보장합니다. 핵심 아이디어: **같은 계산이라도 시간이 다르면 완전히 다른 증명이 생성**됩니다.

### 5.1 Epoch (`epoch.rs`)

시간을 이산적 단위로 나눕니다:

```
Epoch = floor(unix_timestamp / 3600)

예시:
  00:00 ~ 00:59 → Epoch 0
  01:00 ~ 01:59 → Epoch 1
  02:00 ~ 02:59 → Epoch 2
  ...
```

주요 메서드:
- `Epoch::from_timestamp(secs)` — 타임스탬프 → epoch 변환
- `Epoch::current()` — 현재 시스템 시간의 epoch (std 전용)
- `epoch.next()` / `epoch.prev()` — 인접 epoch
- `epoch.contains_timestamp(ts)` — 해당 타임스탬프가 이 epoch에 속하는지
- `epoch.distance(&other)` — 두 epoch 간 거리

### 5.2 WarpingParams (`warping.rs`)

각 epoch마다 **결정론적으로** 생성되는 암호학적 파라미터 세트입니다:

```rust
pub struct WarpingParams {
    pub epoch: Epoch,
    pub domain_separator: [u8; 32],  // 도메인 분리 해시
    pub salt: [u8; 32],             // FRI 쿼리용 솔트
    pub fri_seed: [u8; 32],         // FRI 랜덤성 시드
}
```

**파라미터 생성 과정 (`WarpingParams::generate`):**

```
입력: seed (비밀), epoch

1. base_params = Poseidon2(seed ∥ epoch ∥ SYSTEM_SALT, "ZKMTD::MTD::Parameters")

2. domain_separator = Poseidon2(base_params ∥ "DOMAIN", "MTD_DOMAIN_SEP")

3. salt = Poseidon2(base_params ∥ "SALT", "MTD_SALT")

4. fri_seed = Poseidon2(base_params ∥ "FRI", "MTD_FRI_SEED")
```

**결정론적 특성**: 같은 seed + epoch → 항상 같은 파라미터 (prover와 verifier가 독립적으로 동일한 파라미터 재생성 가능)

**비결정론적 특성**: epoch이 하나만 달라져도 세 파라미터 모두 완전히 다른 값으로 변합니다.

### 5.3 MTDManager (`manager.rs`)

epoch 전환과 파라미터 생성/캐싱을 관리합니다:

```
┌─────────────────────────────────────┐
│            MTDManager               │
│                                     │
│  seed: Vec<u8>                      │
│  current_epoch: Epoch               │
│  current_params: WarpingParams      │
│  cache: VecDeque<WarpingParams>     │  ← LRU 캐시 (최대 16개)
│  auto_advance: bool                 │
│                                     │
│  Methods:                           │
│  ├─ advance()      → 다음 epoch로     │
│  ├─ sync()         → 시스템 시간 동기   │
│  ├─ get_params(e)  → 특정 epoch 파라미터│
│  └─ validate_timestamp(ts)          │
└─────────────────────────────────────┘
```

**`advance()` 동작:**
1. `current_params`를 캐시에 저장 (캐시 가득차면 가장 오래된 것 제거)
2. `current_epoch = current_epoch.next()`
3. 새 epoch에 대한 `WarpingParams::generate()` 호출
4. `current_params` 업데이트

**`sync()` 동작 (std 전용):**
- 시스템 시간으로 현재 epoch 확인
- 뒤처져 있으면 동기화 (캐시 클리어)
- 시간이 뒤로 갔으면 에러 반환 (시계 조작 방지)

**`get_params(epoch)` 동작:**
1. 현재 epoch이면 즉시 반환
2. 캐시에서 검색
3. 캐시 미스 시 `WarpingParams::generate()`로 재생성 후 캐시에 추가

**`validate_timestamp(ts)` 동작:**
- epoch 범위에 ±300초(5분) 허용 오차 적용

### 5.4 EntropySource (`entropy.rs`)

암호학적으로 안전한 랜덤 바이트를 제공합니다:

| 구현체 | 환경 | 소스 | 보안 |
|--------|------|------|------|
| `SystemEntropy` | std | `getrandom` (OS CSPRNG) | 256-bit |
| `SolanaEntropy` | Solana | slot_hash + Poseidon2 | 256-bit |
| `DeterministicEntropy` | 테스트 | LCG | 비보안 |

`SystemEntropy`는 OS별 CSPRNG을 사용합니다:
- Linux: `/dev/urandom`
- macOS: `arc4random_buf`
- Windows: `BCryptGenRandom`

---

## 6. Batching 모듈 — 배치 처리와 Merkle Tree

### 6.1 BatchProver (`aggregator.rs`)

여러 증명을 한 번에 생성합니다:

```
BatchProver::prove_batch(witnesses, public_inputs)
    │
    ├─ 입력 검증: 개수 일치, 빈 배치 거부, 최대 1000개 제한
    │
    └─ for each (witness, inputs):
        └─ MTDProver::prove(witness, inputs) → Proof
```

`create_proof_batch(proofs, epoch)` 함수:

```
create_proof_batch(proofs, epoch)
    │
    ├─ 1. 모든 proof의 epoch 일치 확인
    │
    ├─ 2. 각 proof.data를 Poseidon2로 해시 → leaf
    │
    ├─ 3. MerkleTree::new(leaves) → Merkle root 계산
    │
    └─ 4. ProofBatch { proofs, merkle_root, epoch }
```

### 6.2 MerkleTree (`merkle.rs`)

이진 해시 트리로 증명들의 무결성을 집계합니다:

```
        [Root]
       /      \
    [H01]    [H23]
    /  \     /  \
  [L0] [L1] [L2] [L3]
   │    │    │    │
  P0   P1   P2   P3  (증명들)
```

**트리 구축:**
- 리프 = `Poseidon2(proof.data, "ZKMTD::Merkle")`
- 내부 노드 = `combine_hashes(left, right, "ZKMTD::Merkle")`
- 홀수 개 리프 시 마지막 노드를 자기 자신과 결합

**Merkle Path 검증:**
`MerklePath.verify(leaf)` — 리프에서 루트까지 sibling 해시를 따라가며 재계산한 루트가 저장된 루트와 일치하는지 확인합니다.

### 6.3 BatchVerifier (`batch_verifier.rs`)

배치 검증 시 수행하는 4단계:

```
BatchVerifier::verify_batch(batch, public_inputs)
    │
    ├─ 1. 배치 크기 검증 (proofs.len == inputs.len, 비어있지 않음)
    │
    ├─ 2. epoch 일관성 (모든 proof.epoch == batch.epoch)
    │
    ├─ 3. Merkle root 재계산 후 constant_time_eq로 대조
    │
    └─ 4. 개별 증명 검증 (각각 MTDVerifier::verify())
```

개별 증명의 배치 포함 여부도 검증 가능합니다:

```
verify_single_in_batch(batch, index, public_inputs)
    │
    ├─ epoch 확인
    ├─ Merkle path 생성 → path.verify(leaf)
    └─ MTDVerifier::verify(proof, inputs)
```

---

## 7. Utils 모듈 — 해시, 압축, 상수

### 7.1 Poseidon2 해시 (`hash.rs`)

ZKMTD의 모든 해시 연산에 사용되는 핵심 함수입니다.

**구현 스펙:**
- **필드**: Goldilocks (p = 2^64 - 2^32 + 1)
- **S-box**: x^7 (Goldilocks에 최적화)
- **Width**: 16 필드 원소
- **Rate**: 8 필드 원소 (입력 흡수)
- **Capacity**: 8 필드 원소 (128-bit 보안)
- **출력**: 32 bytes (4개 필드 원소)

**Sponge 구조 (`poseidon_hash`):**

```
poseidon_hash(data, domain)
    │
    ├─ 1. 상태 초기화: state = [0; 16]
    │
    ├─ 2. 도메인 분리 흡수
    │      └─ domain을 8-byte 청크로 나눠 state[0..RATE]에 주입
    │      └─ permute(state)  ← Poseidon2 순열
    │
    ├─ 3. 데이터 흡수 (sponge absorption)
    │      └─ data를 64-byte(=8*RATE) 청크로 나눠 반복:
    │          └─ state[i] += field_element(chunk_i)
    │          └─ permute(state)
    │
    └─ 4. 출력 추출 (squeezing)
           └─ state[0..4]의 canonical u64 → le_bytes
           └─ → [u8; 32]
```

**Poseidon2 인스턴스는 결정론적으로 초기화됩니다:**
```rust
const ZKMTD_POSEIDON2_SEED: u64 = 0x5A4B4D54445F5032; // "ZKMTD_P2"
let mut rng = ChaCha20Rng::seed_from_u64(ZKMTD_POSEIDON2_SEED);
Poseidon2::new_from_rng_128(...)
```
→ 모든 실행에서 동일한 라운드 상수가 생성됩니다.

**보조 함수들:**
- `combine_hashes(left, right, domain)` — 두 해시를 결합 (Merkle tree용)
- `derive_mtd_params(seed, epoch, salt)` — MTD 파라미터 유도
- `constant_time_eq_fixed::<N>(a, b)` — 고정 크기 배열 타이밍 공격 방지 비교 (XOR 누적, early exit 없음)
- `constant_time_eq(a, b)` — 가변 길이 타이밍 공격 방지 비교 (`max(a.len(), b.len())` 반복)
- `bytes_to_field(bytes)` → Goldilocks 필드 원소로 변환
- `hash_to_field(hash)` → 해시를 필드 원소로

### 7.2 압축 (`compression.rs`)

증명 데이터를 무손실 압축합니다:

| 알고리즘 | 적용 기준 | 방식 |
|---------|----------|------|
| `None` | < 100 bytes | 압축 안 함 |
| `Rle` | >= 100 bytes | Run-Length Encoding |

**압축 무결성 보장:**
```
CompressedProof::compress(proof, algorithm)
    │
    ├─ 1. checksum = Poseidon2(original_data, "COMPRESSION_CHECKSUM")
    ├─ 2. compressed_data = rle_compress(original_data)
    ├─ 3. 즉시 decompress하여 원본과 대조 (무결성 검증)
    └─ → CompressedProof { original_size, compressed_data, checksum, ... }

CompressedProof::decompress()
    │
    ├─ 1. decompressed = rle_decompress(compressed_data)
    ├─ 2. 크기 확인: decompressed.len == original_size
    ├─ 3. checksum 재계산 후 대조 (변조 탐지)
    └─ → Proof
```

### 7.3 상수 (`constants.rs`)

프로토콜 전반에서 사용되는 50+ 상수:

```rust
// 시간
EPOCH_DURATION_SECS: 3600          // 1시간
TIMESTAMP_TOLERANCE_SECS: 300      // ±5분 허용

// 크기 제한
MIN_WITNESS_SIZE: 4                // 최소 4개 원소
MAX_BATCH_SIZE: 1000               // 배치 최대 1000개

// 암호학
MIN_ENTROPY_BITS: 128              // 최소 엔트로피
RECOMMENDED_ENTROPY_BITS: 256      // 권장 엔트로피
FRI_FOLDING_FACTOR: 4
FRI_NUM_QUERIES: 100
MTD_PARAM_CACHE_SIZE: 16           // LRU 캐시 크기

// Solana
SOLANA_MAX_COMPUTE_UNITS: 200,000
SOLANA_BASE_CU: 5,000
SOLANA_PER_BYTE_CU: 10

// 온체인 경량 검증 CU 상수
ONCHAIN_BASE_CU: 500
ONCHAIN_HASH_CU: 100
ONCHAIN_BUFFER_CU: 200

// 도메인 분리 태그 (23개, 해시 충돌 방지 — 유일성 테스트 적용)
DOMAIN_PROOF_GENERATION:  "ZKMTD::ProofGeneration"
DOMAIN_PROOF_VERIFICATION: "ZKMTD::ProofVerification"
DOMAIN_MTD_PARAMS:        "ZKMTD::MTD::Parameters"
DOMAIN_MERKLE:            "ZKMTD::Merkle"
DOMAIN_COMMITMENT:        "ZKMTD::Commitment"
DOMAIN_MTD_DOMAIN_SEP:    "MTD_DOMAIN_SEP"
DOMAIN_MTD_SALT:          "MTD_SALT"
DOMAIN_MTD_FRI_SEED:      "MTD_FRI_SEED"
DOMAIN_PROOF_INTEGRITY:   "PROOF_INTEGRITY"
DOMAIN_SEED_FINGERPRINT:  "SEED_FINGERPRINT"
DOMAIN_COMPRESSION_CHECKSUM: "COMPRESSION_CHECKSUM"
DOMAIN_SOLANA_ENTROPY:    "SOLANA_ENTROPY_V1"
...
```

---

## 8. Solana 모듈 — 온체인 경량 검증

`solana-program` feature 활성화 시 사용 가능합니다.

### 문제

전체 STARK 검증은 ~500K CU가 필요하지만, Solana의 트랜잭션 한도는 200K CU입니다.

### 해결: 2단계 검증

```
┌─ 오프체인 ─────────────────────────┐   ┌─ 온체인 (Solana) ────────────┐
│                                    │   │                              │
│  IntegratedProver.prove_fibonacci() │   │  OnchainVerifier             │
│       │                            │   │       │                      │
│       ▼                            │   │       ▼                      │
│  IntegratedProof (전체 STARK)       │──▶│  LightweightProof            │
│       │                            │   │  (~500 bytes)                │
│       ▼                            │   │       │                      │
│  로컬 검증: ✓ (전체 STARK 검증)     │   │       ▼                      │
│                                    │   │  verify_commitment()         │
│                                    │   │  ~15K CU ✓                   │
└────────────────────────────────────┘   └──────────────────────────────┘
```

- **LightweightProof**: 전체 증명에서 바인딩 해시, epoch, public values만 추출
- **OnchainVerifier**: 커밋먼트 해시만 재계산하여 일치 여부 확인
- 전체 STARK 검증 없이도 "이 증명이 특정 epoch/seed에 바인딩되어 있다"는 것을 확인 가능

---

## 9. 전체 데이터 흐름

### 9.1 기본 증명 생성/검증 흐름

```
[사용자]
   │
   │ seed, witness, public_inputs
   ▼
┌──────────────────────────────────────────────────────────┐
│ IntegratedProver::new(seed, epoch)                        │
│   │                                                      │
│   ├─ MTDManager::with_epoch(seed, epoch)                 │
│   │   └─ WarpingParams::generate(seed, epoch)            │
│   │       ├─ derive_mtd_params(seed, epoch, SYSTEM_SALT) │
│   │       ├─ domain_separator = hash(base ∥ "DOMAIN")    │
│   │       ├─ salt = hash(base ∥ "SALT")                  │
│   │       └─ fri_seed = hash(base ∥ "FRI")               │
│   │                                                      │
│   └─ RealStarkProver::new(SimpleAir::fibonacci())        │
│                                                          │
│ prover.prove_fibonacci(num_rows, pv_salt)                 │
│   │                                                      │
│   ├─ [STARK] 실행 트레이스 생성 (Fibonacci 수열)            │
│   ├─ [STARK] FRI + Merkle 커밋먼트 → STARK 증명            │
│   ├─ [COMMIT] committed_hash = hash(PV ∥ pv_salt)        │
│   ├─ [MTD] binding_hash = hash(PV ∥ committed_hash       │
│   │        ∥ value_count ∥ epoch ∥ params)                │
│   │                                                      │
│   └─ → IntegratedProof {                                 │
│          stark_proof, epoch: 100,                        │
│          params: WarpingParams { ... },                  │
│          binding_hash: [u8; 32],                         │
│          committed_public_values: CommittedPublicInputs,  │
│          pv_salt: Option<[u8; 32]>  // GDPR 삭제용       │
│        }                                                 │
└──────────────────────────────────────────────────────────┘
   │
   │ IntegratedProof
   ▼
┌──────────────────────────────────────────────────────────┐
│ IntegratedVerifier::new(seed, epoch)  (독립적으로 생성 가능) │
│                                                          │
│ verifier.verify(proof)                                   │
│   │                                                      │
│   ├─ epoch 일치 확인                                      │
│   ├─ WarpingParams 일치 확인                               │
│   ├─ binding_hash 재계산 후 대조                            │
│   └─ p3_uni_stark::verify() (STARK 검증)                  │
│                                                          │
│   → true / false                                         │
└──────────────────────────────────────────────────────────┘
```

### 9.2 Epoch 전환 시

```
시간 경과: Epoch 100 → Epoch 101

   prover.advance_epoch()
      │
      ├─ MTDManager.advance()
      │   ├─ 이전 params를 캐시에 저장
      │   ├─ current_epoch = 101
      │   └─ current_params = WarpingParams::generate(seed, 101)
      │       └─ 완전히 새로운 domain_separator, salt, fri_seed
      │
      └─ 결과: Epoch 100의 증명은 Epoch 101 검증자에서 거부됨
               (epoch 불일치 → false)
```

### 9.3 배치 처리 흐름

```
[N개의 witness/inputs]
        │
        ▼
  BatchProver.prove_batch()
        │
        ├─ Proof_0 = prover.prove(w_0, i_0)
        ├─ Proof_1 = prover.prove(w_1, i_1)
        ├─ ...
        └─ Proof_{N-1}
              │
              ▼
  create_proof_batch(proofs, epoch)
        │
        ├─ leaves = [hash(P_0.data), hash(P_1.data), ...]
        ├─ MerkleTree::new(leaves) → root
        └─ ProofBatch { proofs, merkle_root, epoch }
              │
              ▼
  BatchVerifier.verify_batch(batch, inputs)
        │
        ├─ Merkle root 재계산 & 대조
        └─ 각 proof 개별 검증
```

---

## 10. Committed Public Inputs — 프라이버시 (Privacy-by-Default)

모든 증명은 `public_values`를 Poseidon2 + salt로 커밋합니다. 별도의 "standard mode"는 없으며, 프라이버시가 기본값입니다. 온체인에는 해시만 기록되어 GDPR를 준수합니다.

### 10.1 Two-Layer Commitment 설계

```
오프체인: STARK가 real public_values로 증명
         + committed_hash = Poseidon2(public_values || pv_salt, DOMAIN_PV_COMMIT)
         + binding_hash에 committed_hash + value_count 포함 (도메인: ZKMTD_BINDING)

온체인:   committed_hash만 전송 (평문 public_values 불필요)

GDPR 삭제: pv_salt 삭제 → committed_hash 역산 불가 → 익명 데이터
```

### 10.2 핵심 타입

- **`CommittedPublicInputs`** (`core/types.rs`): `commit(values, salt)` / `verify(values, salt)` 메서드 제공
- **`IntegratedProof`** 필드: `committed_public_values: CommittedPublicInputs` (항상 존재), `pv_salt: Option<[u8; 32]>` (GDPR 삭제용, pub(crate) — 외부에서는 `erase_salt()`/`has_salt()` 사용)
- **`IntegratedProver`** 증명 메서드 (모두 committed):
  - `prove_fibonacci(num_rows, pv_salt)` — Fibonacci 증명
  - `prove_sum(a, b, pv_salt)` — 덧셈 증명
  - `prove_multiplication(a, b, pv_salt)` — 곱셈 증명
  - `prove_range(value, threshold, pv_salt)` — 범위 증명
- **`IntegratedVerifier::verify(&proof)`**: binding hash + STARK 검증 (AIR 타입 자동 분기)
- **`IntegratedVerifier::verify_with_salt(proof, values, salt)`**: salt 포함 전체 검증

### 10.3 Soundness 보장

`binding_hash`가 STARK 증명의 실제 `public_values`와 `committed_hash`를 동시에 바인딩합니다.
다른 값으로 커밋먼트를 위조할 경우 binding hash가 불일치하여 검증이 실패합니다.

### 10.4 GDPR 삭제 시나리오

```rust
// 1. 증명 생성 (privacy-by-default)
let proof = prover.prove_fibonacci(8, pv_salt)?;

// 2. 온체인 제출 (committed_hash만)
let hash = proof.committed_values_hash();

// 3. GDPR 삭제 요청 시
proof.erase_salt();  // salt 제거 → 커밋먼트 역산 불가
// 온체인 해시는 더 이상 개인정보가 아님 (CNIL 2018 블록체인 가이드라인)
```

### 10.5 성능 영향

| 항목 | 추가 비용 |
|------|----------|
| 증명 생성 | Poseidon2 해시 1회 (~0.01ms) |
| 검증 | Poseidon2 해시 2회 (~0.02ms) |
| 온체인 CU | +33 bytes → ~330 CU (15K CU 내) |

---

## 11. 보안 설계

### 11.1 양자 내성

- **해시 기반 STARK**: 타원곡선(ECDLP)이 아닌 Poseidon2 해시 기반
- Goldilocks 필드 위의 FRI 프로토콜 → Grover's algorithm에 대한 내성 (128-bit security)

### 11.2 Replay 공격 방지

- 증명에 epoch의 WarpingParams가 바인딩됨
- epoch가 변하면 파라미터 세트 전체가 교체
- 이전 epoch의 증명은 새 epoch에서 검증 불가

### 11.3 메모리 보안

- `Witness`는 `ZeroizeOnDrop` — 스코프 종료 시 자동 소거
- `IntegratedProof.pv_salt`은 `erase_salt()` 호출 시 `zeroize` 크레이트로 안전하게 소거 (컴파일러 최적화 방지)
- `Debug` 출력에서 witness 데이터와 pv_salt은 `<redacted>`로 표시

### 11.4 타이밍 공격 방지

- `constant_time_eq_fixed::<N>()` — 고정 크기 배열 비교. XOR 누적, early exit 없음. 모든 암호학적 비교(`CommittedPublicInputs::verify`, `BatchVerifier` Merkle root, `ProofCommitment::verify`)에 사용
- `constant_time_eq()` — 가변 길이 슬라이스 비교. `max(a.len(), b.len())` 횟수만큼 반복하여 길이 불일치 시에도 타이밍 누출 방지
- `MTDManager`는 `Zeroize + Drop`을 구현하여 seed가 스코프 종료 시 안전하게 소거됩니다

### 11.5 도메인 분리

같은 데이터라도 용도가 다르면 다른 해시값이 나옵니다:

```
hash("data", "ZKMTD::ProofGeneration")  ≠
hash("data", "ZKMTD::ProofVerification") ≠
hash("data", "ZKMTD::Merkle")
```

이는 다른 컨텍스트의 해시값이 의도치 않게 일치하는 것을 방지합니다.

### 11.6 입력 검증

모든 외부 입력은 사용 전 검증됩니다:
- Witness 최소 크기: 4개 원소
- Seed 비어있으면 거부
- StarkConfig: 모든 파라미터 범위/정합성 검사
- Entropy: 최소 128-bit, 암호학적 보안 확인
- Batch: 최대 1000개, 입력 개수 일치 확인
- Epoch: overflow 검사, 시간 역행 탐지

### 11.7 `no_std` / `no_alloc` 지원

임베디드/Solana 온체인 환경을 위해 `std` 없이도 동작합니다:
- `heapless::Vec` (고정 크기 컬렉션) 사용
- 에러 메시지 `&'static str`로 대체
- `#![forbid(unsafe_code)]` — unsafe 코드 완전 금지

### 11.8 128-bit Soundness

STARK 증명 시스템은 128-bit 보안 수준을 제공합니다:

```
FRI 파라미터:
- log_blowup = 2 → blowup factor = 4 → 2 bits per query
- num_queries = 60 → 60 × 2 = 120 bits from queries
- proof_of_work_bits = 8 → 8 bits from PoW grinding

총 보안 강도: 120 + 8 = 128 bits
```

Grover's algorithm에 대해서도 128-bit 보안을 유지하며, Shor's algorithm에는 면역입니다 (타원곡선 미사용).

### 11.9 퍼징 테스트 (Fuzzing)

`cargo-fuzz` + libFuzzer 기반 5개 퍼징 타겟이 구현되어 있습니다:

| 타겟 | 테스트 대상 | 실행 횟수 |
|------|-----------|----------|
| `fuzz_proof_deserialize` | SolanaAdapter 역직렬화 | 5M+ |
| `fuzz_proof_generation` | MTDProver 증명 생성 | 5M+ |
| `fuzz_lightweight_proof` | OnchainVerifier 검증 | 5M+ |
| `fuzz_merkle_tree` | MerkleTree 구축/검증 | 5M+ |
| `fuzz_compression` | 압축/해제 무결성 | 5M+ |

**결과**: 24M+ 누적 실행, 0 crashes, 0 panics

```bash
cd fuzz && cargo +nightly fuzz run fuzz_proof_deserialize
```

### 11.10 코드 커버리지

`cargo-llvm-cov`로 측정한 라인 커버리지:

```
전체 커버리지: 85.57%

모듈별:
- core/types.rs:      90%+
- stark/real_stark.rs: 85%+
- mtd/warping.rs:     88%+
- batching/merkle.rs: 92%+
- utils/hash.rs:      95%+
```

```bash
cargo llvm-cov --features "std,full-p3"
```

---

## 12. 테스트 구조

### 12.1 테스트 분류

| 분류 | 위치 | 테스트 수 | 설명 |
|------|------|----------|------|
| 단위 테스트 | `src/**/*.rs` 내부 | 150+ | 각 모듈의 함수 단위 검증 |
| 통합 테스트 | `tests/*.rs` | 80+ | 모듈 간 상호작용 검증 |
| Property 테스트 | `tests/property_tests.rs` | 10+ | proptest 기반 속성 검증 |
| 퍼징 테스트 | `fuzz/fuzz_targets/*.rs` | 5 | 랜덤 입력 기반 견고성 검증 |

### 12.2 테스트 실행

```bash
# 전체 테스트
cargo test --features "std,full-p3"

# no_std 호환성
cargo test --no-default-features --features alloc

# 특정 테스트
cargo test --features "std,full-p3" test_integrated_fibonacci

# 커버리지 포함
cargo llvm-cov --features "std,full-p3"
```

### 12.3 Soundness 테스트

`tests/soundness.rs`에서 다양한 변조 시나리오를 검증합니다:
- 바인딩 해시 변조 → 검증 실패
- epoch 불일치 → 검증 실패
- public values 변조 → 검증 실패
- Merkle root 변조 → 배치 검증 실패
