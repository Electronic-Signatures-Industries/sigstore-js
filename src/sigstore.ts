import { ec } from 'elliptic'
import 'rxjs'
import { Client, generators, Issuer } from 'openid-client'
import { ethers } from 'ethers'
import axios from 'axios'

export class Sigstore {
  oidcDeviceCodeFlow = false

  /**
   * Enable/disable SSL hostname verification
   */
  sslVerfication = true

  /**
   * URL of Fulcio instance
   */
  fulcioInstanceURL = 'https://fulcio.sigstore.dev'

  /**
   * Client ID for OIDC Identity Provider
   */
  oidcClientID = 'sigstore'

  /**
   * URL of OIDC Identity Provider Authorization endpoint
   */
  oidcAuthURL = 'https://oauth2.sigstore.dev/auth/auth'

  oidcIssuer = 'https://oauth2.sigstore.dev/auth'

  /**
   * URL of OIDC Identity Provider Token endpoint
   */
  oidcTokenURL = 'https://oauth2.sigstore.dev/auth/token'

  /**
   * URL of OIDC Identity Provider Device Code endpoint
   */
  oidcDeviceCodeURL = 'https://oauth2.sigstore.dev/auth/device/code'

  /**
   * URL of Rekor instance
   */
  rekorInstanceURL = 'https://rekor.sigstore.dev'

  /**
   * URL of Trusted Timestamp Authority (RFC3161 compliant)
   */
  tsaURL = 'https://tsp.pki.gob.pa/tsr'
  kp: any

  constructor(private privateKey?: string, private publicKey?: string) {
    const alg = new ec('secp256k1')

    if (privateKey) {
      this.kp = alg.keyFromPrivate(privateKey)
    } else {
      this.kp = alg.genKeyPair()
    }
  }

  // Issuer {
  //   authorization_endpoint: 'https://oauth2.sigstore.dev/auth/auth',
  //   claim_types_supported: [
  //     'normal'
  //   ],
  //   claims_parameter_supported: false,
  //   claims_supported: [
  //     'iss',
  //     'sub',
  //     'aud',
  //     'iat',
  //     'exp',
  //     'email',
  //     'email_verified',
  //     'locale',
  //     'name',
  //     'preferred_username',
  //     'at_hash'
  //   ],
  //   code_challenge_methods_supported: [
  //     'S256',
  //     'plain'
  //   ],
  //   device_authorization_endpoint: 'https://oauth2.sigstore.dev/auth/device/code',
  //   grant_types_supported: [
  //     'authorization_code',
  //     'refresh_token',
  //     'urn:ietf:params:oauth:grant-type:device_code'
  //   ],
  //   id_token_signing_alg_values_supported: [
  //     'RS256'
  //   ],
  //   issuer: 'https://oauth2.sigstore.dev/auth',
  //   jwks_uri: 'https://oauth2.sigstore.dev/auth/keys',
  //   request_parameter_supported: false,
  //   request_uri_parameter_supported: true,
  //   require_request_uri_registration: false,
  //   response_modes_supported: [
  //     'query',
  //     'fragment'
  //   ],
  //   response_types_supported: [
  //     'code'
  //   ],
  //   scopes_supported: [
  //     'openid',
  //     'email',
  //     'groups',
  //     'profile',
  //     'offline_access'
  //   ],
  //   subject_types_supported: [
  //     'public'
  //   ],
  //   token_endpoint: 'https://oauth2.sigstore.dev/auth/token',
  //   token_endpoint_auth_methods_supported: [
  //     'client_secret_basic',
  //     'client_secret_post'
  //   ],
  //   userinfo_endpoint: 'https://oauth2.sigstore.dev/auth/userinfo'
  // }

  async getOIDCToken(email: string): Promise<string> {
    let client: Client
    try {      
      const issuer = await Issuer.discover(this.oidcIssuer);
      client = new issuer.Client({
        redirect_uris: ['http://localhost:3000/#/callback'],
        client_id: this.oidcClientID,
      }) as Client

      // device code flow support
      // TODO: store the code_verifier in your framework's session mechanism, if it is a cookie based solution
      // it should be httpOnly (not readable by javascript) and encrypted.
      const code_verifier = generators.codeVerifier()
      
      // Create challenge
      const code_challenge = generators.codeChallenge(code_verifier)

      const urlChallenge = await client.authorizationUrl({
        scope: 'openid email profile',
        code_challenge,
        code_challenge_method: 'S256',
      })

      // Must be call by user. Callback 'http://localhost:3000/#/callback'
      // https://github.com/panva/node-openid-client
      // const resp = await axios({
      //   method: 'GET',
      //   url: urlChallenge,
      // })

      console.log(resp)
      debugger

      // String emailFromIDToken = (String) parsedIdToken.getPayload().get("email");
      // Boolean emailVerified = (Boolean) parsedIdToken.getPayload().get("email_verified");
      // if (expectedEmailAddress != null && !emailFromIDToken.equals(expectedEmailAddress)) {
      //     throw new InvalidObjectException(
      //             String.format("email in ID token '%s' does not match address specified to plugin '%s'",
      //                     emailFromIDToken, emailAddress));
      // } else if (Boolean.FALSE.equals(emailVerified)) {
      //     throw new InvalidObjectException(
      //             String.format("identity provider '%s' reports email address '%s' has not been verified",
      //                     parsedIdToken.getPayload().getIssuer(), emailAddress));
      // }
      // this.emailAddress = emailFromIDToken;

      // return idTokenString;
    } catch (e) {
      throw new Error('Error signing email address')
    }

    return ''
  }

  async signEmailAddress(email: string): Promise<string> {
    try {
      if (this.kp === null) {
        throw new Error('private key must be specified')
      }
      if (email === null) {
        throw new Error('email address must not be null')
      } else {
        // EmailValidator ev = EmailValidator.getInstance();
        // if (!ev.isValid(emailAddress)) {
        //     throw new Error(String.format("email address specified '%s' is invalid", emailAddress));
        // }
      }
      const digest = ethers.utils.sha256(ethers.utils.toUtf8Bytes(email))
      const sig = this.kp.sign(digest)

      return ethers.utils.base64.encode(sig)
    } catch (e) {
      throw e
    }
  }

  async getSigningCertificates(
    signEmailAddress: string,
    idToken: string,
  ): Promise<string> {
    try {
      const publicKeyB64 = ethers.utils.base64.encode(
        ethers.utils.toUtf8Bytes(this.kp.getPublic().encode('hex')),
      )
      const res = await axios({
        method: 'POST',
        url: `${this.fulcioInstanceURL}/api/v1/signingCert`,
        data: {
          signEmailAddress,
          publicKey: {
            algorithm: 'ecdsa',
            content: publicKeyB64,
          },
        },
        headers: {
          Accept: 'application/pem-certificate-chain',

          Authorization: `Bearer ${idToken}`,
        },
      })

      // return raw PEM string
      return res.data
    } catch (e) {
      throw new Error('bad response' + e.message)
    }
  }

  async signData(data: Uint8Array, certs: any): Promise<string> {
    // try {
    //   const digest = ethers.utils.sha256(data)
    //   const der = await tsp.request(this.tsaURL, digest)
    //   const resp = await tsp.parse(der)
    //   console.log(resp.asn.timeStampToken)
    //   return resp.asn.timeStampToken;
    // } catch (e) {
    //   throw new Error(e.message)
    // }
    return Promise.resolve("");
  }

  async registerRekorLog(signedData: string) {
    try {
      const payload = ethers.utils.base64.encode(
        ethers.utils.toUtf8Bytes(signedData),
      )
      const res = await axios({
        method: 'POST',
        url: `${this.rekorInstanceURL}/api/v1/log/entries`,
        data: {
          kind: 'text',
          apiVersion: '0.0.1',
          spec: {
            archive: {
              content: payload,
            },
          },
        },
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
      })

      return res.headers['Location']
    } catch (e) {
      throw new Error('bad response' + e.message)
    }
  }
}
