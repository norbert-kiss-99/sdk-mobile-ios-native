import SwiftUI
import AuthenticationServices

struct WebauthnLoginView: View {
    @EnvironmentObject var loginController: LoginController

    // periphery:ignore
    let screen: String
    let formId: String
    // periphery:ignore
    let widgetId: String

    let widget: WebauthnLoginWidget

    let action: (() async -> Void)?
    
    @State var delegate: WebauthnDelegate? = nil

    init(screen: String, formId: String, widgetId: String, widget: WebauthnLoginWidget, action: @escaping () async -> Void) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        self.action = action
    }

    init(screen: String, formId: String, widgetId: String, widget: WebauthnLoginWidget) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        action = nil
    }
    
    private func createDeviceBiometricsRequest() -> ASAuthorizationPlatformPublicKeyCredentialAssertionRequest {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: widget.assertionOptions.rpId
        )
        
        let challenge = widget.assertionOptions.challenge.base64URLDecode()!
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        
        request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: widget.assertionOptions.userVerification) ?? .preferred
        request.allowedCredentials = widget.assertionOptions.allowCredentials.compactMap({ allowCredential in
            if let id = allowCredential.id.base64URLDecode() {
                return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
            }
            return nil
        })
        
        return request
    }
    
    private func createSecurityKeyRequest() -> ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest {
        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
            relyingPartyIdentifier: widget.assertionOptions.rpId
        )
        
        let challenge = widget.assertionOptions.challenge.base64URLDecode()!
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        
        request.allowedCredentials = widget.assertionOptions.allowCredentials.compactMap({ allowCredential in
            if let id = allowCredential.id.base64URLDecode() {
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: id, transports: allowCredential.transports.map({ transport in
                    return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport(transport)
                }))
            }
            return nil
        })
        request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: widget.assertionOptions.userVerification) ?? .discouraged
        
        return request
    }
    
    private func loginWebauthn() {
        guard let request: ASAuthorizationRequest = switch widget.authenticatorType {
            case "deviceBiometrics": createDeviceBiometricsRequest()
            case "securityKey": createSecurityKeyRequest()
            default: nil
        } else {
            print("Unsupported authenticator type: \(widget.authenticatorType)")
            FallbackTriggerView()
            return
        }
            
        let controller = ASAuthorizationController(authorizationRequests: [request])
            
        delegate = WebauthnDelegate(loginController: loginController, formId: formId, widgetId: widgetId) {
            await loginController.submit(formId: formId)
        } onError: { error in
            print("Error during webauthn login: \(error.localizedDescription)")
        }

        controller.delegate = delegate
        controller.performRequests()
    }

    var body: some View {
        let button = Button {
            Task {
                if action != nil {
                    await action?()
                } else {
                    loginWebauthn()
                }
            }
        } label: { Text(widget.label) }

        switch widget.render?.type {
        case "button":
            button
                .buttonStyle(.borderedProminent)

        default:
            FallbackTriggerView()
        }
    }
}
