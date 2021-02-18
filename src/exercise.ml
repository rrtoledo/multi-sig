open Bls12_381

(* h0: H_0 hash function
Input: G1 element, String
Output: G1 element
The function hashes the string into a scalar and returns the g1 element input raised with it.

Remarks: Because of the use of the function 'int_of_string' to convert a hex string into a decimal string, I had to use only a few bytes of the hash digest which leads to a security risk. This can be corrected by defining and using an helper function instead of using 'int_of_string'. TODO
*)
let h0 x y = 
  let sha_instance = Sha256.string y in
  let digest = String.sub (Sha256.to_hex sha_instance) 0 8 in
  let digest = Int.to_string (int_of_string ("0x" ^ digest)) in
  let exponent = Fr.of_string digest in
  let g1_element = G1.Uncompressed.mul x exponent in
  g1_element


(* h1: H_1 hash function
Input: string
Output: Fr
The function hashes the string into a scalar and returns it.

Remarks: Because of the use of the function 'int_of_string' to convert a hex string into a decimal string, I had to use only a few bytes of the hash digest which leads to a security risk. This can be corrected by defining and using an helper function instead of using 'int_of_string'. TODO
*)
let h1 x =
  let sha_instance = Sha256.string x in
  let digest = String.sub (Sha256.to_hex sha_instance) 0 8 in
  let digest = Int.to_string (int_of_string ("0x" ^ digest)) in
  let exponent = Fr.of_string digest in
  exponent


(* parGen: Parameter Generation 
Input: None
Output: g1, g2, e
  - g1: a generator of G1
  - g2: a generator of G2
  - e: a pairing function
The function returns random generators of G1 and G2 and an alias of the pairing operation.

Remarks: We assume that we are using BLS12-381, as such we do not output the prime and group descriptions.
*)
let parGen = 
  let g1 = G1.Uncompressed.random () in
  let g2 = G2.Uncompressed.random () in 
  let e = Pairing.pairing in 
  g1, g2, e


(* keyGen: Key generation 
Input: None
Output: (sk, pk)
  - secret key sk
  - public key g_2^sk
The function returns a random secret key and the public key associated to it.
*)
let keyGen par =
 let _, g2, _ = par in
 let a = Fr.random () in 
 a, G2.Uncompressed.mul g2 a


(* keyAgg: Key aggregation
Input: {pk_i}_i
  - set of public keys pk_i
Output: apk
  - apk is the aggregated key defined as:
    apk = Prod( pk_i^{H_1(pk_i, {pk_i}_i)} ) where H_1 is a hash function returning a scalar
The function returns the aggregated public key apk.
*)
let keyAgg set_pk =
  let concatenated_pk = List.fold_left (fun x y -> Bytes.cat x (G2.Uncompressed.to_bytes y)) Bytes.empty set_pk in
  List.fold_left (fun x y ->
    let to_hash = Bytes.to_string (Bytes.cat (G2.Uncompressed.to_bytes y) concatenated_pk) in
    let hash_scalar = h1 to_hash in
    let group_element = G2.Uncompressed.mul y hash_scalar in
    G2.Uncompressed.add x group_element
  ) G2.Uncompressed.zero set_pk


(* sign: Signing function
Input: par, {pk_i}_i, sk_i, m
  - public parameters par
  - set of public {pk_i}_i
  - secret key sk_i
  - message to sign m
Output: sig
  - signature sig defined as:
    sig = H_0(m)^{a_i * sk_i} where a_i = H_1(pk_i, {sk_i}_i)
The function returns a signature on message m generated with the secret key sk_i and the set of public keys {pk_i}_i.
*)
let sign par set_pk sk m =
  let g1, g2, _ = par in
  let pk = G2.Uncompressed.mul g2 sk in
  let concatenated_pk = List.fold_left (fun x y -> Bytes.cat x (G2.Uncompressed.to_bytes y)) Bytes.empty set_pk in
  let a_i = h1 (Bytes.to_string (Bytes.cat (G2.Uncompressed.to_bytes pk) concatenated_pk)) in
  let group_element = h0 g1 m in
  let exponent = Fr.mul a_i sk in
  G1.Uncompressed.mul group_element exponent


(* singleVf: Signature Verification 
Input: par, pk_i, {pk_j}_j, m, sig
Output: 0/1
  - return 1 if e(sig, g_2^-1) * e(H_0(m), pk_i) = 0_gt
This function checks if a before-combined signature is valid. This function is not defined in Compact Multi-Signatures for Smaller Blockchains section 3.1.
*)
let singleVf par pki set_pk m signature =
  let g1, g2, e = par in 
  let group_element = h0 g1 m in
  let concatenated_pk = List.fold_left (fun x y -> Bytes.cat x (G2.Uncompressed.to_bytes y)) Bytes.empty set_pk in
  let a_i = h1 (Bytes.to_string (Bytes.cat (G2.Uncompressed.to_bytes pki) concatenated_pk)) in
  let gt_element1 = e signature g2 in
  let gt_element2 = e group_element (G2.Uncompressed.mul pki a_i) in
  Fq12.eq gt_element1 gt_element2

(* signCb: Signature Combining
Input: par, {sig_i}_i
  - public parameter par
  - set of signatures {sig_i}_i
Output: sigma
  - combined signature sigma defined as:
    sigma = Prod( sig_i ) (if the public key set are the same and the signature are on the same message)
This function combines several signatures into a final signature called sigma.

Remarks: we may want to update this function to take as inputs the public key sets and the messages ({sig_i, msg_i {pk_j}_j}_i instead of {sig_i}_i) as well as add a boolean to this signature so that if set to true, we check the validity of the individidual signatures before combining them, that is if they are defined on the same message and same set of public keys and if they verify.
*)
let signCb list_signatures =
  List.fold_left (fun x y -> G1.Uncompressed.add x y) G1.Uncompressed.zero list_signatures


(* multiVf: Multi-Signature Verification 
Input: par, apk, m, sigma
  - public parameter par
  - aggregated public key apk
  - message m
  - combined/finalized signature sigma
Output: 0/1
  - return 1 if e(sigma, g_2^-1) * e(H_0(m), apk) = 1_gt, 0 otherwise
This function checks the validity of a finalized/combined signature.
*)
let multiVf par apk m sigma =
  let g1, g2, e = par in 
  let group_element = h0 g1 m in
  let gt_element1 = e sigma g2 in
  let gt_element2 = e group_element apk in
  Fq12.eq gt_element1 gt_element2


(* listSet: 
Input: list
Output: boolean
Check if the input list has elements with occurence stricly higher than 1 . The function returns true if at least one element is duplicated, false otherwise
*)
let listSet inputList = 
  let bool, _ = List.fold_left( fun x y -> 
    let bool, set = x in
    if Bool.not bool then
      if List.mem y set then
        true, set
      else
        bool,  y :: set
    else
      bool, set
  ) (false, []) inputList in
  bool

(* batchVf: Batch verification 
Input: par, {sigma_i, m_i, apk_i}_i
  - public parameter par
  - finalized signature tuple
    - combined/finalized signature sigma
    - message m
    - aggregated public key apk
Output: 0/1
The function combines different signatures and batch their verification.
*)
let batchVf par list_transcript =
  let g1, g2, e = par in
  let list_msg = List.fold_left (fun x y -> 
    let _, m_j, _ = y in
    x @ [m_j]) [] list_transcript in
  let sigma, gt_product = List.fold_left (fun x y ->
    let sigma, gt_product = x in
    let sigma_i, m_i, apk_i = y in
    if (listSet list_msg) then
      let sigma = G1.Uncompressed.add sigma sigma_i in
      let gt_element = e (h0 g1 m_i) apk_i in
      let gt_product = Fq12.mul gt_product gt_element in
      sigma, gt_product
    else
      let random_coin = Fr.random () in 
      let sigma = G1.Uncompressed.add sigma (G1.Uncompressed.mul sigma_i random_coin) in
      let gt_element = e (h0 g1 m_i) (G2.Uncompressed.mul apk_i random_coin) in
      let gt_product = Fq12.mul gt_product gt_element in
      sigma, gt_product
  ) (G1.Uncompressed.zero, Fq12.one) list_transcript in
  Fq12.eq (e sigma g2) gt_product