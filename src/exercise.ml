(* Example call of a functor to obtain a finite field module. *)
module Fr = Ff.MakeFp (struct
  let prime_order = Z.of_string "13"
end)

(* Example definition of a data structure. *)
type point = {x: Fr.t; y : Fr.t}

(* Instance of the above type. *)
let zero = {x=Fr.zero; y=Fr.zero}

(* A function generating random elements of the above type. *)
let random () = {x=Fr.random (); y=Fr.random ()}

(* Type annotations are not mandatory but can be helpful to debug sometimes. *)
let add (a:point) b =
  let x = Fr.(a.x + b.x) in
  let y = Fr.(a.y + b.y) in
  {x;y}

let to_string a =
  Format.sprintf "{%s; %s}" (Fr.to_string a.x) (Fr.to_string a.y)

(* Example of use of the Bls libary *)
let z = Bls12_381.G1.Compressed.zero
