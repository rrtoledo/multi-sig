open Exercise

let test_addition_zero () =
  assert (add zero zero = zero)

let test_addition a =
  assert (add a zero = a)

let () =
  Format.printf "Testing\n";
  test_addition_zero ();
  test_addition (random ());
