class SignatureMissingException extends Error {}
class SignatureInvalidException extends Error {}

const UNSIGNABLE_HEADERS = ['x-forwarded-proto', 'x-real-ip'];

const unsignedError = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Unauthenticated requests are not allowed for this API</Message>
</Error>`;

const validationError = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Sender</Type>
    <Code>SignatureDoesNotMatch</Code>
    <Message>Signature validation failed.</Message>
  </Error>
  <RequestId>0300D815-9252-41E5-B587-F189759A21BF</RequestId>
</ErrorResponse>`;

// Filter out headers that shouldn't be included in the signature
function filterHeaders({ headers, unsignableHeaders = UNSIGNABLE_HEADERS }: FilterHeadersParams): HeadersInit {
  const result: HeadersInit = {};
  headers.forEach((value, key) => {
    if (!unsignableHeaders.includes(key) && !key.startsWith('cf-')) {
      result[key] = value;
    }
  });
  return result;
}

// Verify the signature on the incoming request
async function verifySignature({ request, accessKeyId }: VerifySignatureParams): Promise<void> {
  const authorization = request.headers.get('Authorization');
  if (!authorization) {
    throw new SignatureMissingException();
  }

  const re = /^AWS4-HMAC-SHA256 Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=(.+)$/;
  const match = authorization.match(re);
  if (!match) {
    throw new SignatureInvalidException();
  }

  const [, credential, signedHeaders, signature] = match;
  const credentialParts = credential.split('/');

  if (credentialParts[0] !== accessKeyId) {
    throw new SignatureInvalidException();
  }

  const datetime = request.headers.get('x-amz-date') || '';
  const headersToSign = signedHeaders.split(';').reduce((obj: { [key: string]: string }, key) => {
    const value = request.headers.get(key);
    if (value) {
      obj[key] = value;
    }
    return obj;
  }, {});

  const aws = new AwsClient({
    accessKeyId,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
    service: 's3',
    region: aws_region,
  });

  const signedRequest = await aws.sign(request.url, {
    method: request.method,
    headers: headersToSign,
    body: request.body,
    aws: { datetime, allHeaders: true },
  });

  const signedAuth = signedRequest.headers.get('Authorization') || '';
  const [, , , generatedSignature] = signedAuth.match(re) || [];

  if (signature !== generatedSignature) {
    throw new SignatureInvalidException();
  }
}

// Handle the incoming request
async function handleRequest({ event, awsEndpoint, accessKeyId, secretAccessKey, webhookUrl }: HandleRequestParams): Promise<Response> {
  const request = event.request;
  const url = new URL(request.url);
  url.hostname = awsEndpoint;

  try {
    await verifySignature({ request, accessKeyId });
  } catch (e) {
    return new Response(
      e instanceof SignatureMissingException ? unsignedError : validationError,
      {
        status: 403,
        headers: {
          'Content-Type': 'application/xml',
          'Cache-Control': 'max-age=0, no-cache, no-store',
        },
      }
    );
  }

  const headers = filterHeaders({ headers: request.headers });
  const aws = new AwsClient({
    accessKeyId,
    secretAccessKey,
    service: 's3',
    region: aws_region,
  });

  const signedRequest = await aws.sign(url.toString(), {
    method: request.method,
    headers,
    body: request.body,
  });

  const response = await fetch(signedRequest);

  if (webhookUrl) {
    const contentLength = parseInt(request.headers.get('content-length') || '0', 10);
    const webhookPayload: WebhookPayload = {
      contentLength: contentLength || null,
      contentType: request.headers.get('content-type'),
      method: request.method,
      signatureTimestamp: request.headers.get('x-amz-date'),
      status: response.status,
      url: response.url,
    };

    event.waitUntil(
      fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(webhookPayload),
      })
    );
  }

  return response;
}

addEventListener('fetch', (event: FetchEvent) => {
  event.respondWith(
    handleRequest({
      event,
      awsEndpoint: AWS_S3_ENDPOINT,
      accessKeyId: AWS_ACCESS_KEY_ID,
      secretAccessKey: AWS_SECRET_ACCESS_KEY,
      webhookUrl: WEBHOOK_URL,
    })
  );
});