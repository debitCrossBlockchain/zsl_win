#ifndef _LIB_ZSL_H_
#define _LIB_ZSL_H_
#include <stdlib.h> 
#include <inttypes.h>
#include <stdbool.h>
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
using namespace std;
using namespace libsnark;
class LibZsl
{

public:
	LibZsl() {}
	~LibZsl() {}
	void zsl_initialize();
	bool zsl_verify_shielding(
		void* proof,
		void* send_nf,
		void* cm,
		uint64_t value
	);
	void zsl_prove_shielding(
		void* rho,
		void* pk,
		uint64_t value,
		void* output_proof
	);
	void zsl_paramgen_shielding();

	void zsl_prove_unshielding(
		void* rho,
		void* sk,
		uint64_t value,
		uint64_t tree_position,
		void* authentication_path,
		void* output_proof
	);
	bool zsl_verify_unshielding(
		void* proof_ptr,
		void* spend_nf_ptr,
		void* rt_ptr,
		uint64_t value
	);

	void zsl_paramgen_unshielding();

	void zsl_paramgen_transfer();

	void zsl_prove_transfer(
		void* output_proof_ptr,
		void* input_rho_ptr_1,
		void* input_pk_ptr_1,
		uint64_t input_value_1,
		uint64_t input_tree_position_1,
		void* input_authentication_path_ptr_1,
		void* input_rho_ptr_2,
		void* input_pk_ptr_2,
		uint64_t input_value_2,
		uint64_t input_tree_position_2,
		void* input_authentication_path_ptr_2,
		void* output_rho_ptr_1,
		void* output_pk_ptr_1,
		uint64_t output_value_1,
		void* output_rho_ptr_2,
		void* output_pk_ptr_2,
		uint64_t output_value_2
	);

	bool zsl_verify_transfer(
		void* proof_ptr,
		void* anchor_ptr,
		void* spend_nf_ptr_1,
		void* spend_nf_ptr_2,
		void* send_nf_ptr_1,
		void* send_nf_ptr_2,
		void* cm_ptr_1,
		void* cm_ptr_2
	);
};

#endif