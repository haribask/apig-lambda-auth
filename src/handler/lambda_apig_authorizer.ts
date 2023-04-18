import log from 'lambda-log';
import { AuthResponse, CustomAuthorizerEvent, PolicyDocument } from 'aws-lambda';
import ParamService from '../service/paramservice';
import { CredData } from '../util/requestresponsetypes';
const OktaJwtVerifier = require('@okta/jwt-verifier');
import jwtDecode, { JwtPayload } from 'jwt-decode';

export const apigAuthorizer = async (event: CustomAuthorizerEvent) => {
  const paramservice: ParamService = new ParamService({});

  const tokenInHeader = String(event?.authorizationToken).includes("Bearer") ? event?.authorizationToken?.split(" ") : [];
  if (!tokenInHeader?.length) {
    log.info('Token not supplied for Authorization purpose');
    return generatePolicy("*","Deny","*");
  }
  const bearerToken = tokenInHeader[1];
  const splitBearerToken = String(bearerToken).includes('.') ? bearerToken?.split('.') : [];

  if (typeof splitBearerToken[1] === 'undefined' || splitBearerToken[1].length < 64) {
    log.info('Bearer token is not valid');
    return generatePolicy("*","Deny","*");
  }

  const parsed_jwt: JwtPayload = jwtDecode(bearerToken);
  const cid = parsed_jwt.sub != undefined ? parsed_jwt.sub : "";
  const tokenIssuer = parsed_jwt.iss != undefined ? parsed_jwt.iss : "";
  const audience = parsed_jwt.aud != undefined ? parsed_jwt.aud : "";

  if(cid == "") {
    log.info('cid missing in decoded token');
    return generatePolicy("*","Deny","*");
  } else {
      try {
          const oktaCerts = new OktaJwtVerifier({
            issuer: tokenIssuer
          });

          const jwt = await oktaCerts.verifyAccessToken(bearerToken, audience);
          var claims = jwt.claims;

          if (claims == undefined) {
            log.info('Token failed verification');
            return generatePolicy("*","Deny","*");
          } else {
            const secretname: string = (process.env.SECRET_NAME as string);
            const paramValue = await paramservice.getParameter({paramKey: secretname,isSecret: true});
            
            if (paramValue.success && paramValue.item) {
                const credData: CredData = JSON.parse(paramValue.item);
                if(claims.cid == credData.customerid){
                  log.info('success - Allow policy');
                  return generatePolicy("*","Allow","*");
                } else {
                  log.info('failed - Deny policy');
                  return generatePolicy("*","Deny","*");
                }
            }
        } 
      } catch (error) {
          log.info('JWT Token is not a valid JSON Object');
          return generatePolicy("*","Deny","*");
      }
    }
}

var generatePolicy = function(principalId: string, effect: string, resource: string) {
  var authResponse = {} as AuthResponse;
  
  authResponse.principalId = principalId;
  if (effect && resource) {
      var policyDocument = {} as PolicyDocument;
      policyDocument.Version = '2012-10-17'; 
      policyDocument.Statement = [];
      const statementOne: any = {};
      statementOne.Action = 'execute-api:Invoke'; 
      statementOne.Effect = effect;
      statementOne.Resource = resource;
      policyDocument.Statement[0] = statementOne;
      authResponse.policyDocument = policyDocument;
    }

  return authResponse;
}
