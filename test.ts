import { Sigstore } from './src/sigstore'

const bootstrap = async () => {
  const sigstore = new Sigstore()
  await sigstore.initialize();

  const data = Buffer.from('Hello World')

  // -----------  proof of  email issuer ----------------
  // 1. POST /proofs/request
  // { email: '' }
   // response tokenset 


  // OIDC Authentication - Frontend
  const tokenset: any = await sigstore.getOIDCToken('molekilla@gmail.com')
  console.log(tokenset.id_token)

  // 2. User authenticates con verification_uri_complete


  // 3. Signed email (browser)
  const signedEmail = await sigstore.signEmailAddress(tokenset.id_token)
  console.log(signedEmail) //

  // POST /proofs/enroll
  // { idToken, email, publicKey, signedEmail, paymentSignature }
  // TODO: Certificates stored in IPFS
  // TODO: Requires getOIDCToken authenticated
  const pem = await sigstore.getSigningCertificates(signedEmail, tokenset.id_token)
  // as is, 'application/pem-certificate-chain'

// ----------------
  // PAYWALL 1 - 10
  // Certificate ROOT CA - 20 minutes - 6 h

  // POST /proofs/timestamp
  // { signature, publicKey } 
  console.log(pem)
  // https://github.com/opentimestamps/javascript-opentimestamps
}

bootstrap()
debugger
