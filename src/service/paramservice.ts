import {SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import log from 'lambda-log';
import { ServiceResponse } from "../util/requestresponsetypes";

const PATH_TO_SECRETS_MANAGER = '/aws/reference/secretsmanager/'

const AWS_REGION : string = (process.env.AWS_REGION  as string)?? (process.env.REGION  as string);

const client = new SSMClient({region: AWS_REGION});
const DEFAULT_SYSTEM = "pmtctrl";
const DEFAULT_SUB_SYSTEM = "";
const DEFAULT_ENVIRONMENT = "dev";
const ROOT = "csaa";

export interface ParamInput  { 
    paramKey: string,
    secure?: boolean,
    isSecret?: boolean,
    isResolvePath?: boolean
}

interface ParameterStoreSettings {
    root: string;
    system: string;
    environment: string;
}
  
export interface ParameterStoreOptions {
    system?: string;
    environment?: string;
}

export interface ParamOutTemp {
    type: string,
    username: string,
    password:string 
}

export default class ParamService {
    private settings: ParameterStoreSettings;    

    constructor(opts: ParameterStoreOptions) {
        this.settings = {
          root: ROOT,
          system: DEFAULT_SYSTEM,
          environment: DEFAULT_ENVIRONMENT,
          ...opts,
        };
    }

    /**
     * Get Parameter from Parameter store
     * @param paramInput 
     * @returns 
     */
    public async getParameter(paramInput: ParamInput): Promise<ServiceResponse<string>> {
        //log.info('Parameter store region '+ AWS_REGION);
        let paramValue: string='';
        try {
            let paramKey: string; 
            // If isSecret=true , then fetch from Secrets Manager
            if (paramInput.isSecret) {
                paramKey = `${PATH_TO_SECRETS_MANAGER}${paramInput.paramKey}`;
            } // if Resolve Path=true resolve the path to the Parameter
            else if(paramInput.isResolvePath) {
                paramKey = this.resolvePath(paramInput.paramKey,paramInput.secure);
            } // Use the Parameter with or without path
            else {
                paramKey = paramInput.paramKey;
            }
            log.info('The Parameter To fetch is '+ paramKey);

            // SSM Call to parameter store
            const inputCommand = new GetParameterCommand({Name: paramKey, WithDecryption: true});
            const response = await client.send(inputCommand);
            log.info('Param Value ------->: '+ response.Parameter);

            // Retrieve the Parameter Value
            if(response.Parameter && response.Parameter.Value) {
                paramValue = response.Parameter.Value
                log.info('Param Value is -->-->--> '+ paramValue);
            }
        }
         catch (error) {
            // SSM API Error
            log.info('Exception while fetching the Parameter '+ paramInput.paramKey, {error} )
            return {
                success: false
            }
        }
        // At this stage no issue, return the retrieved param value
        return {
            success: true,
            item: paramValue
        }
    }

    /**
     * Resolve the path to Parameter for standard dynamic path
     * @param paramKey 
     * @returns 
     */
    private resolvePath(paramKey:string, secure: boolean=false): string {
        const path = [
            this.settings.root,
            this.settings.system,
            this.settings.environment,
            secure ? "secure" : "insecure",
            paramKey
          ].join("/");
      
          return `/${path}`;
    }
}