open Exercise
open Bls12_381

let test_single_signature () = 
  let par = parGen in
  let sk, pk = keyGen par in
  let set_pk = [pk] in
  let msg = "Hello World!\n" in
  let signature = sign par set_pk sk msg in
  assert (singleVf par pk set_pk msg signature)

let test_apk () = 
  let par = parGen in
  let _, pk1 = keyGen par in
  let _, pk2 = keyGen par in
  let set_pk = pk1 :: [pk2] in
  let apk = keyAgg set_pk in
  let concatenated_pk = List.fold_left (fun x y -> Bytes.cat x (G2.Uncompressed.to_bytes y)) Bytes.empty set_pk in
  let a_1 = h1 (Bytes.to_string (Bytes.cat (G2.Uncompressed.to_bytes pk1) concatenated_pk)) in
  let a_2 = h1 (Bytes.to_string (Bytes.cat (G2.Uncompressed.to_bytes pk2) concatenated_pk)) in
  let apk_manual = G2.Uncompressed.add (G2.Uncompressed.mul pk1 a_1) (G2.Uncompressed.mul pk2 a_2) in
  assert (G2.Uncompressed.eq apk apk_manual)

let test_sigma () = 
  let par = parGen in
  let sk1, pk1 = keyGen par in
  let sk2, pk2 = keyGen par in
  let set_pk = pk1 :: [pk2] in
  let msg = "Hello World!" in
  let signature1 = sign par set_pk sk1 msg in
  let signature2 = sign par set_pk sk2 msg in
  let set_signature = signature1 :: [signature2] in
  let sigma = signCb set_signature in
  assert (G1.Uncompressed.eq sigma (G1.Uncompressed.add signature1 signature2))

let test_multi_signature () = 
  let par = parGen in
  let sk1, pk1 = keyGen par in
  let sk2, pk2 = keyGen par in
  let set_pk = pk1 :: [pk2] in
  let msg = "Hello World!" in
  let signature1 = sign par set_pk sk1 msg in
  let signature2 = sign par set_pk sk2 msg in
  let set_signature = signature1 :: [signature2] in
  let sigma = signCb set_signature in
  let apk = keyAgg set_pk in
  assert (multiVf par apk msg sigma)

let test_batch_same_message () = 
  let par = parGen in
  let sk1, pk1 = keyGen par in
  let sk2, pk2 = keyGen par in
  let sk3, pk3 = keyGen par in
  let set_pk1 = pk1 :: [pk2] in
  let set_pk2 = pk2 :: [pk3] in
  let msg = "Hello World!" in
  let signature11 = sign par set_pk1 sk1 msg in
  let signature12 = sign par set_pk1 sk2 msg in
  let signature21 = sign par set_pk2 sk2 msg in
  let signature22 = sign par set_pk2 sk3 msg in
  let set_signature1 = signature11 :: [signature12] in
  let set_signature2 = signature21 :: [signature22] in
  let sigma1 = signCb set_signature1 in
  let sigma2 = signCb set_signature2 in
  let apk1 = keyAgg set_pk1 in
  let apk2 = keyAgg set_pk2 in
  let transcript = (sigma1, msg, apk1) :: [(sigma2, msg, apk2)] in
  assert (batchVf par transcript)

let test_batch_diff_message () = 
  let par = parGen in
  let sk1, pk1 = keyGen par in
  let sk2, pk2 = keyGen par in
  let sk3, pk3 = keyGen par in
  let set_pk1 = pk1 :: [pk2] in
  let set_pk2 = pk2 :: [pk3] in
  let msg1 = "Hello World!" in
  let msg2 = "Hello Earth!" in
  let signature11 = sign par set_pk1 sk1 msg1 in
  let signature12 = sign par set_pk1 sk2 msg1 in
  let signature21 = sign par set_pk2 sk2 msg2 in
  let signature22 = sign par set_pk2 sk3 msg2 in
  let set_signature1 = signature11 :: [signature12] in
  let set_signature2 = signature21 :: [signature22] in
  let sigma1 = signCb set_signature1 in
  let sigma2 = signCb set_signature2 in
  let apk1 = keyAgg set_pk1 in
  let apk2 = keyAgg set_pk2 in
  let transcript = (sigma1, msg1, apk1) :: [(sigma2, msg2, apk2)] in
  assert (batchVf par transcript)


let () =
  Format.printf "----- Testing Compact Multi-Signatures for Smaller Blockchains\n";
  Format.printf "-- testing test_single_signature: ";
  test_single_signature ();
  Format.printf "passed\n";
  Format.printf "-- testing test_apk: ";
  test_apk ();
  Format.printf "passed\n";
  Format.printf "-- testing test_sigma: ";
  test_sigma ();
  Format.printf "passed\n";
  Format.printf "-- testing test_multi_signature: ";
  test_multi_signature ();
  Format.printf "passed\n";
  Format.printf "-- testing test_batch_same_message: ";
  test_batch_same_message ();
  Format.printf "passed\n";
  Format.printf "-- testing test_batch_diff_message: ";
  test_batch_diff_message ();
  Format.printf "passed\n";
