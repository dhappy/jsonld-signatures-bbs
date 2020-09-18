/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  Bls12381G2KeyPair,
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} from "@mattrglobal/jsonld-signatures-bbs";
import { extendContextLoader, sign, verify, purposes } from "jsonld-signatures";
import { documentLoaders } from "jsonld";

import inputDocument from "./data/inputDocument.json";
import keyPairOptions from "./data/keyPair.json";
import exampleControllerDoc from "./data/controllerDocument.json";
import bbsContext from "./data/lds-bbsbls2020-v0.0.json";
import revealDocument from "./data/deriveProofFrame.json";
import citizenVocab from "./data/citizenVocab.json";

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const documents: any = {
  "did:example:489398593#test": keyPairOptions,
  "did:example:489398593": exampleControllerDoc,
  "https://w3c-ccg.github.io/ldp-bbs2020/context/v1": bbsContext,
  "https://w3id.org/citizenship/v1": citizenVocab
};

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const customDocLoader = (url: string): any => {
  const context = documents[url];

  if (context) {
    return {
      contextUrl: null, // this is for a context via a link header
      document: context, // this is the actual document that was loaded
      documentUrl: url // this is the actual context URL after redirects
    };
  }

  return documentLoaders.node()(url);
};

//Extended document load that uses local contexts
/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const documentLoader: any = extendContextLoader(customDocLoader);

const main = async (): Promise<void> => {
  //Import the example key pair
  const keyPair = await new Bls12381G2KeyPair(keyPairOptions);

  console.log("Input document");
  console.log(JSON.stringify(inputDocument, null, 2));

  //Sign the input document
  const signedDocument = await sign(inputDocument, {
    suite: new BbsBlsSignature2020({ key: keyPair }),
    purpose: new purposes.AssertionProofPurpose(),
    compactProof: false,
    documentLoader
  });

  console.log("Input document with proof");
  console.log(JSON.stringify(inputDocument, null, 2));

  //Sign the input document again
  const signedDocument2 = await sign(inputDocument, {
    suite: new BbsBlsSignature2020({ key: keyPair }),
    purpose: new purposes.AssertionProofPurpose(),
    compactProof: false,
    documentLoader
  });

  console.log("Input document with 2 proofs");
  console.log(JSON.stringify(inputDocument, null, 2));

  //Verify the proof
  let verified = await verify(inputDocument, {
    suite: new BbsBlsSignature2020(),
    purpose: new purposes.AssertionProofPurpose(),
    compactProof: false,
    documentLoader
  });

  console.log("Verification result");
  console.log(JSON.stringify(verified, null, 2));

  //Derive a proof
  const derivedProof = await deriveProof(inputDocument, revealDocument, {
    suite: new BbsBlsSignatureProof2020(),
    compactProof: false,
    documentLoader
  });

  console.log("Derived proof");
  console.log(JSON.stringify(derivedProof, null, 2));

  //Verify the derived proof
  verified = await verify(derivedProof, {
    suite: new BbsBlsSignatureProof2020(),
    purpose: new purposes.AssertionProofPurpose(),
    compactProof: false,
    documentLoader
  });

  console.log("Verification result");
  console.log(JSON.stringify(verified, null, 2));
};

main();
