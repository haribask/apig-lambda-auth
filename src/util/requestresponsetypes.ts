export interface ServiceResponse<T> {
    success: boolean;
    errorCode?: number | null;
    errorMessage?: string;
    item?: T;
} 
export interface CredData {
  type: string,
  username: string,
  password:string,
  clientid: string,
  clientsecret: string,
  apigclientid: string
}

