import SwiftUI
import AuthenticationServices

struct PasskeyLoginView: View {
    @EnvironmentObject var loginController: LoginController

    // periphery:ignore
    let screen: String
    let formId: String
    // periphery:ignore
    let widgetId: String

    let widget: PasskeyLoginWidget

    let action: (() async -> Void)?
    
    @State var delegate: WebauthnDelegate? = nil

    init(screen: String, formId: String, widgetId: String, widget: PasskeyLoginWidget, action: @escaping () async -> Void) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        self.action = action
    }

    init(screen: String, formId: String, widgetId: String, widget: PasskeyLoginWidget) {
        self.screen = screen
        self.formId = formId
        self.widgetId = widgetId
        self.widget = widget
        action = nil
    }
    
    private func loginPasskey() {
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
        
        let controller = ASAuthorizationController(authorizationRequests: [request])
        
        delegate = WebauthnDelegate(loginController: loginController, formId: formId, widgetId: widgetId) {
            await loginController.submit(formId: formId)
        } onError: { error in
            print("Error during passkey login: \(error.localizedDescription)")
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
                    loginPasskey()
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
