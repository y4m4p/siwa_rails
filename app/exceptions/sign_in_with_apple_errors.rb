class SignInWithAppleErrors < StandardError
  class ConnectionFailed < SignInWithAppleErrors; end
  class ValidationError < SignInWithAppleErrors; end
  class ExpiredToken < ValidationError; end
  class InvalidSignature < ValidationError; end
  class InvalidIssuer < ValidationError; end
  class AudienceMismatch < ValidationError; end
  class SubjectMismatch < ValidationError; end
  class NonceMismatch < ValidationError; end
  class AuthorizationCodeMismatch < ValidationError; end
  class EndUserClaimMismatch < ValidationError; end
end
