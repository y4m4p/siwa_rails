class SignInWithAppleConst
  APPLE_PRIVATE_ADDRESS_DOMAIN = "@privaterelay.appleid.com"

  if ENV["APPLE_PRIVATE_KEY"].present?
    PRIVATE_KEY = OpenSSL::PKey::EC.new(ENV["APPLE_PRIVATE_KEY"])
  else
    PRIVATE_KEY = ""
  end
end
