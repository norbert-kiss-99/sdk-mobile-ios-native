import SwiftUI
import AuthenticationServices

struct PasskeyEnrollView: View {
    @EnvironmentObject var loginController: LoginController

    // periphery:ignore
    let screen: String
    let formId: String
    // periphery:ignore
    let widgetId: String

    let widget: PasskeyEnrollWidget

    let action: (() async -> Void)?
    
    @State var delegate: WebauthnDelegate? = nil

    init(screen: String, formId: String, widgetId: String, widget: PasskeyEnrollWidget, action: @escaping () async -> Void) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        self.action = action
    }

    init(screen: String, formId: String, widgetId: String, widget: PasskeyEnrollWidget) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        action = nil
    }
    
    private func registerPasskey() {
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
    
        let controller = ASAuthorizationController(authorizationRequests: [request])
        
        delegate = WebauthnDelegate(loginController: loginController, formId: formId, widgetId: widgetId) {
            await loginController.submit(formId: formId)
        } onError: { error in
            print("Error during passkey enroll: \(error.localizedDescription)")
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
                    registerPasskey()
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
