import AuthenticationServices

public class WebauthnDelegate: NSObject, ASAuthorizationControllerDelegate {
    
    let onFinish: (() async -> Void)
    let onError: ((Error) async -> Void)
    
    let loginController: LoginController
    let formId: String
    let widgetId: String
    
    init(
        loginController: LoginController,
        formId: String,
        widgetId: String,
        onFinish: @escaping (() async -> Void),
        onError: @escaping ((Error) async -> Void)
    ) {
        self.loginController = loginController
        self.formId = formId
        self.widgetId = widgetId
        
        self.onFinish = onFinish
        self.onError = onError
    }
    
    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            if #available(iOS 16.6, *) {
                loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".authenticatorAttachment", defaultValue: "").wrappedValue = credential.attachment.value()
            } else {
                loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".authenticatorAttachment", defaultValue: "").wrappedValue = "platform"
            }
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".id", defaultValue: "").wrappedValue = credential.credentialID.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".rawId", defaultValue: "").wrappedValue = credential.credentialID.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".type", defaultValue: "").wrappedValue = "public-key"
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.attestationObject", defaultValue: "").wrappedValue = credential.rawAttestationObject?.base64URLEncodedString() ?? ""
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.clientDataJSON", defaultValue: "").wrappedValue = credential.rawClientDataJSON.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.transports", defaultValue: [] as [String]).wrappedValue = ["internal"]
            
            Task { await onFinish() }
        } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".id", defaultValue: "").wrappedValue = credential.credentialID.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".rawId", defaultValue: "").wrappedValue = credential.credentialID.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".type", defaultValue: "").wrappedValue = "public-key"
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.authenticatorData", defaultValue: "").wrappedValue = credential.rawAuthenticatorData.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.clientDataJSON", defaultValue: "").wrappedValue = credential.rawClientDataJSON.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.signature", defaultValue: "").wrappedValue = credential.signature.base64URLEncodedString()
            loginController.bindingForWidget(formId: formId, widgetId: widgetId + ".response.userHandle", defaultValue: "").wrappedValue = String(data: credential.userID, encoding: .utf8)?.urlEncode()
            
            Task { await onFinish() }
        } else {
            let error = NSError(domain: "WebauthnDelegate", code: -1, userInfo: [NSLocalizedDescriptionKey: "Credential is not valid"])
            Task { await onError(error) }
        }
    }
    
    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        Task { await onError(error) }
    }
}

@available(iOS 16.6, *)
fileprivate extension ASAuthorizationPublicKeyCredentialAttachment {
    func value() -> String {
        return switch self {
        case .platform: "platform"
        case .crossPlatform: "cross-platform"
        }
    }
}

