class SignInWithAppleConst
  APPLE_PRIVATE_ADDRESS_DOMAIN = "@privaterelay.appleid.com"

  if ENV["APPLE_PRIVATE_KEY"].present?
    PRIVATE_KEY = OpenSSL::PKey::EC.new(ENV["APPLE_PRIVATE_KEY"])
  else
    PRIVATE_KEY = ""
    Util::CLI::Logger.warn "APPLE_PRIVATE_KEY environment variable is empty and will cause an error if you try to authenticate using Sign in with Apple."
  end
end
