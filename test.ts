import { Sigstore } from './src/sigstore'



const bootstrap = (async () => {

    const sigstore = new Sigstore();

    const data = Buffer.from('Hello World');

    // OIDC Authentication - Frontend
    const idToken = await sigstore.getOIDCToken('molekilla@gmail.com');

    // Signed email
    const signedEmail = await sigstore.signEmailAddress('molekilla@gmail.com');

    // TODO: Requires getOIDCToken authenticated
    const pem = await sigstore.getSigningCertificates(signedEmail, idToken);


    // Certificate ROOT CA - 20 minutes

    // TODO: kaching!
    // Optional
    const sig = await sigstore.signData(data, pem);

    // Optional
    await sigstore.registerRekorLog(sig);
});

bootstrap();
debugger;