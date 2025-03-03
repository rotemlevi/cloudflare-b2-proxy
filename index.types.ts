export interface AwsClientConfig {
  accessKeyId: string;
  secretAccessKey: string;
  service: string;
  region: string;
}

export interface WebhookPayload {
  contentLength: number | null;
  contentType: string | null;
  method: string;
  signatureTimestamp: string | null;
  status: number;
  url: string;
}

export interface VerifySignatureParams {
  request: Request;
  accessKeyId: string;
}

export interface HandleRequestParams {
  env: Environment;
  event: FetchEvent;
  awsEndpoint: string;
  accessKeyId: string;
  secretAccessKey: string;
  webhookUrl?: string;
}

export interface FilterHeadersParams {
  headers: Headers;
  unsignableHeaders: string[];
}