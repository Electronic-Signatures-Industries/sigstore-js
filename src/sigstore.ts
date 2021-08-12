import { ec } from 'elliptic'
import 'rxjs'
import { Client, generators, Issuer } from 'openid-client'
import { ethers, Wallet } from 'ethers'
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
  wallet: ethers.Wallet

  constructor(private privateKey?: string, private publicKey?: string) {
    this.wallet = ethers.Wallet.createRandom()
    this.publicKey = this.wallet.publicKey.substring(2)
    this.privateKey = this.wallet.privateKey.substring(2)
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
  //     'openid',6666666666666444444444
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
      const r = await axios({
        method: 'POST',
        url: this.oidcDeviceCodeURL,
        data: {
          client_id: this.oidcClientID,
          scope: 'openid email',
        },
      })
      const issuer = await Issuer.discover(this.oidcIssuer)
      client = new issuer.Client({
        client_id: this.oidcClientID,
        client_secret: this.publicKey,
      }) as Client

      // device code flow support
      const handle = await client.deviceAuthorization()

      console.log('User Code: ', r)
      console.log('Verification URI: ', handle.verification_uri)
      console.log(
        'Verification URI (complete): ',
        handle.verification_uri_complete,
      )
      const tokenSet = await handle.poll()
      console.log('received tokens %j', tokenSet)

      // return idTokenString;
      return tokenSet.id_token
    } catch (e) {
      throw e
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
      const sig = await this.wallet.signMessage(digest)

      return ethers.utils.base64.encode(Buffer.from(sig))
    } catch (e) {
      throw e
    }
  }

  async getSigningCertificates(
    signEmailAddress: string,
    idToken: string,
  ): Promise<string> {
    console.log({
      method: 'POST',
      url: `${this.fulcioInstanceURL}/api/v1/signingCert`,
      data: {
        signedEmailAddress: signEmailAddress,
        publicKey: {
          algorithm: 'ecdsa',
          content: ethers.utils.base64.encode(Buffer.from(this.publicKey)),
        },
      },
      headers: {
        Accept: 'application/pem-certificate-chain',

        Authorization: `Bearer ${idToken}`,
      },
    })
    try {
      const res = await axios({
        method: 'POST',
        url: `${this.fulcioInstanceURL}/api/v1/signingCert`,
        data: {
          signedEmailAddress: signEmailAddress,
          publicKey: {
            //      algorithm: 'ecdsa',
            content: ethers.utils.base64.encode(Buffer.from(this.publicKey)),
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
      throw e
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
    return Promise.resolve('')
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
