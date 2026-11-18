import {api} from './client.js';
export const forensicsApi={
  chain:()=>api('/forensics/chain'),
  publicKey:()=>api('/forensics/public-key'),
};
