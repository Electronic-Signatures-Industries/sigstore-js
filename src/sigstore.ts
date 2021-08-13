const fetch = require('node-fetch')
import { DIDManager } from 'xdv-universal-wallet-core'
import { RSAKeyGenerator } from 'xdv-universal-wallet-core/lib/did/RSAKeyProvider'
import jwt_decode from 'jwt-decode'

import { ec } from 'elliptic'
import 'rxjs'
import { Client, generators, Issuer } from 'openid-client'
import { ethers, Wallet } from 'ethers'
import axios from 'axios'
import {
  ArrayBuffertohex,
  hextob64,
  hextob64u,
  KEYUTIL,
  KJUR,
  pemtohex,
  RSAKey,
  utf8tob64u,
  X509,
} from 'jsrsasign'
import { base64 } from 'ethers/lib/utils'

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
  rsa: any
  publicKey: any
  sig: KJUR.crypto.Signature

  constructor() {}

  async initialize() {
    const gen = KEYUTIL.generateKeypair("EC", "secp256r1")
    this.sig = new KJUR.crypto.Signature({ alg: 'SHA256withRSA' })
    this.sig.init(gen.prvKeyObj)

    this.kp = KEYUTIL.getKey(gen.prvKeyObj)
    this.publicKey = hextob64(pemtohex(KEYUTIL.getPEM(gen.pubKeyObj)))
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

  async getOIDCToken(email: string): Promise<any> {
    let client: Client
    try {
      const issuer = await Issuer.discover(this.oidcIssuer)
      client = new issuer.Client({
        client_id: this.oidcClientID,
        token_endpoint_auth_method: 'none',
      }) as Client

      // device code flow support
      const handle = await client.deviceAuthorization({
        scope: 'openid email',
        client_id: 'sigstore',
      })

      // console.log('User Code: ', r)
      console.log('Verification URI: ', handle.verification_uri)
      console.log(
        'Verification URI (complete): ',
        handle.verification_uri_complete,
      )
      const tokenSet = await handle.poll()

      return tokenSet
    } catch (e) {
      throw e
    }
  }

  async signEmailAddress(jwt: string): Promise<string> {
    try {
      if (this.kp === null) {
        throw new Error('private key must be specified')
      }
      if (jwt === null) {
        throw new Error('email address must not be null')
      } else {
        // EmailValidator ev = EmailValidator.getInstance();
        // if (!ev.isValid(emailAddress)) {
        //     throw new Error(String.format("email address specified '%s' is invalid", emailAddress));
        // }
      }

      const payload: any = jwt_decode(jwt)
      console.log(payload)
      // const digest = ethers.utils.sha256(Buffer.from(payload.email))

      this.sig.updateString(payload.email)

      const s = this.sig.sign()
      
      return hextob64(s)
    } catch (e) {
      throw e
    }
  }

  async getSigningCertificates(
    signEmailAddress: string,
    idToken: string,
  ): Promise<string> {
    try {
      const res = await fetch(`${this.fulcioInstanceURL}/api/v1/signingCert`, {
        method: 'POST',
        body: JSON.stringify({
          signedEmailAddress: signEmailAddress,
          publicKey: {
            algorithm: 'ecdsa',
            content: (this.publicKey),
          },
        }),
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/pem-certificate-chain',
          Authorization: `Bearer ${idToken}`,
        },
      })

      // return raw PEM string
      return res.text()
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
