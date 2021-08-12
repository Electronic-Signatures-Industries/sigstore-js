import { Sigstore } from './src/sigstore'

const bootstrap = async () => {
  const sigstore = new Sigstore()

  const data = Buffer.from('Hello World')

  // OIDC Authentication - Frontend
  const tokenset: any = await sigstore.getOIDCToken('molekilla@gmail.com')
  console.log(tokenset.id_token)

  // Signed email
  const signedEmail = await sigstore.signEmailAddress('molekilla@gmail.com')
  console.log(signedEmail) //

  // TODO: Requires getOIDCToken authenticated
  const pem = await sigstore.getSigningCertificates(signedEmail, tokenset.id_token)

  // Certificate ROOT CA - 20 minutes
  console.log(pem)
  // TODO: kaching!
  // Optional
  // const sig = await sigstore.signData(data, pem);

  // Optional
  // await sigstore.registerRekorLog(sig);
}

bootstrap()
debugger
