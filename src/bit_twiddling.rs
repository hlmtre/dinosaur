// this exists so i could get a decent understanding of bitwise operations
fn main() {
  let mut byte: u16 = 0b0000_0000_0000_0000;

  println!("set the first bit in each nibble");
  byte |= 0b1000_1000_1000_1000; // Set a bit
  println!("0b{:016b}", byte);

  println!("unset the first bit in the first two nibbles");
  byte &= 0b0111_0111_1111_1111; // Unset a bit
  println!("0b{:016b}", byte);

  println!("toggle the first bit in the first three nibbles");
  byte ^= 0b1000_1000_1000_0000; // Toggle a bit
  println!("0b{:016b}", byte);

  byte = 0b1000_1000_1000_1000;

  println!("shift left 0b1000_1000_1000_1000");
  byte <<= 1; // shift left one bit
  println!("0b{:016b}", byte);

  println!("shift right 0b1000_1000_1000_1000");
  byte >>= 1; // shift right one bit
  println!("0b{:016b}", byte);

  byte = 0b1000_1000_1000_1000;
  let mut mask: u16 = 0b1000_0000_0000_0000;

  println!("mask: 0b{:016b}", mask);
  let mut result = (byte & mask) != 0;
  println!("first bit was set? {:?}", result);
  println!("byte: 0b{:016b}", byte);

  println!("now we check second bit from left");
  mask = 0b0100_0000_0000_0000;
  println!("mask: 0b{:016b}", mask);
  result = (byte & mask) != 0;
  println!("second bit was set? {:?}", result);
  println!("byte: 0b{:016b}", byte);

  println!("now we check first bit in second nibble");
  mask = 0b0000_1000_0000_0000;
  println!("mask: 0b{:016b}", mask);
  result = (byte & mask) != 0;
  println!("first-bit-second-nibble was set? {:?}", result);
  println!("byte: 0b{:016b}", byte);
}
