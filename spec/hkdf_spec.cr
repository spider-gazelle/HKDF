require "./spec_helper"

describe HKDF do
  test_cases = [
    {
      name: "A.1 Test Case 1",
      hash: OpenSSL::Algorithm::SHA256,
      IKM:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".hexbytes,
      salt: "000102030405060708090a0b0c".hexbytes,
      info: "f0f1f2f3f4f5f6f7f8f9".hexbytes,
      len:  42,
      PRK:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".hexbytes,
      OKM:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".hexbytes,
    },
    {
      name: "A.2 Test Case 2",
      hash: OpenSSL::Algorithm::SHA256,
      IKM:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".hexbytes,
      salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".hexbytes,
      info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".hexbytes,
      len:  82,
      PRK:  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244".hexbytes,
      OKM:  "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".hexbytes,
    },
    {
      name: "A.3 Test Case 3",
      hash: OpenSSL::Algorithm::SHA256,
      IKM:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".hexbytes,
      salt: Bytes.new(0),
      info: Bytes.new(0),
      len:  42,
      PRK:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04".hexbytes,
      OKM:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8".hexbytes,
    },
    {
      name: "A.4 Test Case 4",
      hash: OpenSSL::Algorithm::SHA1,
      IKM:  "0b0b0b0b0b0b0b0b0b0b0b".hexbytes,
      salt: "000102030405060708090a0b0c".hexbytes,
      info: "f0f1f2f3f4f5f6f7f8f9".hexbytes,
      len:  42,
      PRK:  "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243".hexbytes,
      OKM:  "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896".hexbytes,
    },
    {
      name: "A.5 Test Case 5",
      hash: OpenSSL::Algorithm::SHA1,
      IKM:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".hexbytes,
      salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".hexbytes,
      info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".hexbytes,
      len:  82,
      PRK:  "8adae09a2a307059478d309b26c4115a224cfaf6".hexbytes,
      OKM:  "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4".hexbytes,
    },
    {
      name: "A.6 Test Case 6",
      hash: OpenSSL::Algorithm::SHA1,
      IKM:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".hexbytes,
      salt: Bytes.new(0),
      info: Bytes.new(0),
      len:  42,
      PRK:  "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01".hexbytes,
      OKM:  "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918".hexbytes,
    },
    {
      name: "A.7 Test Case 7",
      hash: OpenSSL::Algorithm::SHA1,
      IKM:  "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c".hexbytes,
      salt: Bytes.new(0),
      info: Bytes.new(0),
      len:  42,
      PRK:  "2adccada18779e7c2077ad2eb19d3f3e731385dd".hexbytes,
      OKM:  "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48".hexbytes,
    },
  ]

  it "can be validated against the test cases" do
    test_cases.each do |case1|
      puts "running #{case1[:name]}"

      hash_algo = case1[:hash]

      # Extract phase
      salt = case1[:salt]
      ikm = case1[:IKM]
      prk = HKDF.extract(salt, ikm, hash_algo)
      prk.should eq case1[:PRK]

      # Expand phase
      info = case1[:info]
      length = case1[:len]
      okm = HKDF.expand(prk, info, length, hash_algo)
      okm.should eq case1[:OKM]

      # Combined HKDF Extract-and-Expand
      derived_key = HKDF.derive_key(salt, ikm, info, length, hash_algo)
      derived_key.should eq case1[:OKM]
    end
  end
end
