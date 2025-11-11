import SwiftUI
import AuthenticationServices

struct WebauthnEnrollView: View {
    @EnvironmentObject var loginController: LoginController

    // periphery:ignore
    let screen: String
    let formId: String
    // periphery:ignore
    let widgetId: String

    let widget: WebauthnEnrollWidget

    let action: (() async -> Void)?
    
    @State var delegate: WebauthnDelegate? = nil

    init(screen: String, formId: String, widgetId: String, widget: WebauthnEnrollWidget, action: @escaping () async -> Void) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        self.action = action
    }

    init(screen: String, formId: String, widgetId: String, widget: WebauthnEnrollWidget) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        action = nil
    }
    
    private func createDeviceBiometricsRequest() -> ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: widget.enrollOptions.rp.id
        )
        
        let userId = Data(widget.enrollOptions.user.id.utf8)
        let challenge = widget.enrollOptions.challenge.base64URLDecode()!
        let displayName = widget.enrollOptions.user.displayName
    
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: displayName,
            userID: userId
        )
        
        request.attestationPreference = ASAuthorizationPublicKeyCredentialAttestationKind(widget.enrollOptions.attestation)
        if #available(iOS 17.4, *) {
            request.excludedCredentials = widget.enrollOptions.excludeCredentials.compactMap({ excludeCredential in
                if let id = excludeCredential.id.base64URLDecode() {
                    return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
                }
                return nil
            })
        }
        request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: widget.enrollOptions.authenticatorSelection.userVerification) ?? .required
        
        return request
    }
    
    private func createSecurityKeyRequest() -> ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest {
        let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
            relyingPartyIdentifier: widget.enrollOptions.rp.id
        )
        
        let userId = Data(widget.enrollOptions.user.id.utf8)
        let challenge = widget.enrollOptions.challenge.base64URLDecode()!
        let displayName = widget.enrollOptions.user.displayName
    
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            displayName: displayName,
            name: displayName,
            userID: userId
        )
        
        request.attestationPreference = ASAuthorizationPublicKeyCredentialAttestationKind(widget.enrollOptions.attestation)
        request.credentialParameters = widget.enrollOptions.pubKeyCredParams.map({ param in
            return ASAuthorizationPublicKeyCredentialParameters(algorithm: ASCOSEAlgorithmIdentifier(param.alg))
        })
        request.excludedCredentials = widget.enrollOptions.excludeCredentials.compactMap({ excludeCredential in
            if let id = excludeCredential.id.base64URLDecode() {
                return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: id, transports: excludeCredential.transports.map({ transport in
                    return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport(rawValue: transport)
                }))
            }
            return nil
        })
        if (widget.enrollOptions.authenticatorSelection.requireResidentKey) {
            request.residentKeyPreference = ASAuthorizationPublicKeyCredentialResidentKeyPreference(widget.enrollOptions.authenticatorSelection.residentKey)
        }
        request.userVerificationPreference = ASAuthorizationPublicKeyCredentialUserVerificationPreference(rawValue: widget.enrollOptions.authenticatorSelection.userVerification) ?? .discouraged
        
        return request
    }
    
    private func registerWebauthn() {
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
            print("Error during webauthn enroll: \(error.localizedDescription)")
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
                    registerWebauthn()
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
