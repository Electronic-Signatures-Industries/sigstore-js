const { randomBytes } = require('crypto')
const secp256r1 = require('secp256r1')
import * as fetch from 'node-fetch'
import { ec } from 'elliptic'
import 'rxjs'
import { Client, generators, Issuer } from 'openid-client'
import { ethers, Wallet } from 'ethers'
import axios from 'axios'
import { arrayify, hexlify } from 'ethers/lib/utils'
import { DERSerializer, DERDeserializer } from '@complycloud/asn1-der'

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

  constructor(private privateKey?: Uint8Array, private publicKey?: Uint8Array) {
    this.kp = new ec('p256').genKeyPair()
    this.publicKey = this.kp.getPublic().encode()
    this.privateKey = this.kp.getPrivate()
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

  async getOIDCToken(email: string): Promise<any> {
    let client: Client
    try {
      const issuer = await Issuer.discover(this.oidcIssuer)
      client = new issuer.Client({
        client_id: this.oidcClientID,
        client_secret: '000',
      }) as Client

      // device code flow support
      const handle = await client.deviceAuthorization()

      // console.log('User Code: ', r)
      console.log('Verification URI: ', handle.verification_uri)
      console.log(
        'Verification URI (complete): ',
        handle.verification_uri_complete,
      )
      const tokenSet = await handle.poll()
      console.log('received tokens %j', tokenSet)

      // return idTokenString;
      return tokenSet
    } catch (e) {
      throw e
    }
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
      const digest = ethers.utils.sha256(Buffer.from(email))
      const sig = await this.kp.sign(digest)

      const deserializer = new DERDeserializer()
      const asn1 = deserializer(Buffer.from(sig.toDER()))
      console.log(asn1, sig.toDER())

      return ethers.utils.base64.encode(Buffer.from(asn1))
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
            //      algorithm: 'ecdsa',
            content: ethers.utils.base64.encode(this.publicKey),
          },
        }),
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/pem-certificate-chain',
          Authorization: `Bearer ${idToken}`,
        },
      })

      // return raw PEM string
      return res.json()
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
