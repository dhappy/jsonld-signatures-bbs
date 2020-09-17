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

/* eslint-disable @typescript-eslint/no-explicit-any */
import jsonld from "jsonld";
import { suites, SECURITY_CONTEXT_URL } from "jsonld-signatures";
import { blsCreateProof, blsVerifyProof } from "@mattrglobal/bbs-signatures";
import {
  DeriveProofOptions,
  VerifyProofOptions,
  CreateVerifyDataOptions,
  CanonizeOptions
} from "./types";
import { BbsBlsSignature2020 } from "./BbsBlsSignature2020";
import { randomBytes } from "@stablelib/random";
import { VerifyProofResult } from "./types/VerifyProofResult";
import { Bls12381G2KeyPair } from "@mattrglobal/bls12381-key-pair";

export class BbsBlsSignatureProof2020 extends suites.LinkedDataProof {
  constructor({ useNativeCanonize, key, LDKeyClass }: any = {}) {
    super({
      type:
        "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignatureProof2020"
    });

    this.proof = {
      "@context": "https://w3c-ccg.github.io/ldp-bbs2020/context/v1",
      type: "BbsBlsSignatureProof2020"
    };
    this.supportedDeriveProofType =
      "https://w3c-ccg.github.io/ldp-bbs2020/context/v1#BbsBlsSignature2020";

    this.LDKeyClass = LDKeyClass ?? Bls12381G2KeyPair;
    this.proofSignatureKey = "proofValue";
    this.key = key;
    this.useNativeCanonize = useNativeCanonize;
  }

  /**
   * Derive a proof from a proof and reveal document
   *
   * @param options {object} options for deriving a proof.
   *
   * @returns {Promise<object>} Resolves with the derived proof object.
   */
  async deriveProof(options: DeriveProofOptions): Promise<object> {
    //Initialize the BBS signature suite
    const suite = new BbsBlsSignature2020();
    const {
      document,
      proof: proofs,
      revealDocument,
      documentLoader,
      expansionMap,
      compactProof = true
    } = options;
    let { nonce } = options;

    // Get the input document statements
    const documentStatements = await suite.createVerifyDocumentData(document, {
      documentLoader,
      expansionMap,
      compactProof
    });

    // Transform any blank node identifiers for the input
    // document statements into actual node identifiers
    // e.g _:c14n0 => urn:bnid:_:c14n0
    const transformedInputDocumentStatements = documentStatements.map(
      (element: any) => {
        const nodeIdentifier = element.split(" ")[0];
        if (nodeIdentifier.startsWith("_:c14n")) {
          return element.replace(
            nodeIdentifier,
            `<urn:bnid:${nodeIdentifier}>`
          );
        }
        return element;
      }
    );

    //Transform the resulting RDF statements back into JSON-LD
    const compactInputProofDocument = await jsonld.fromRDF(
      transformedInputDocumentStatements.join("\n")
    );

    // Frame the result to create the reveal document result
    const revealDocumentResult = await jsonld.frame(
      compactInputProofDocument,
      revealDocument,
      { documentLoader }
    );

    // Creates a derived proof, functionalized because `proof` can either
    // be a single object or an array of objects and it needs to be called
    // appropriately.
    const derive = async (proof: any): Promise<object | undefined> => {
      if (!proof) {
        return undefined;
      }

      // Validate that the input proof document has a proof compatible with this suite
      if (proof.type !== this.supportedDeriveProofType) {
        throw new TypeError(
          `proof document proof incompatible, expected proof type of ${this.supportedDeriveProofType} received ${proof.type}`
        );
      }

      //Extract the BBS signature from the input proof
      const signature = Buffer.from(proof[this.proofSignatureKey], "base64");

      //Initialize the derived proof
      let derivedProof;
      if (this.proof) {
        // use proof JSON-LD document passed to API
        derivedProof = await jsonld.compact(this.proof, SECURITY_CONTEXT_URL, {
          documentLoader,
          expansionMap,
          compactToRelative: false
        });
      } else {
        // create proof JSON-LD document
        derivedProof = { "@context": SECURITY_CONTEXT_URL };
      }

      // ensure proof type is set
      derivedProof.type = this.type;

      // Get the proof statements
      const proofStatements = await suite.createVerifyProofData(proof, {
        documentLoader,
        expansionMap
      });

      // Canonicalize the resulting reveal document
      const revealDocumentStatements = await suite.createVerifyDocumentData(
        revealDocumentResult,
        {
          documentLoader,
          expansionMap
        }
      );

      //Get the indices of the revealed statements from the transformed input document offset
      //by the number of proof statements
      const numberOfProofStatements = proofStatements.length;

      //Always reveal all the statements associated to the original proof
      //these are always the first statements in the normalized form
      const proofRevealIndices = Array.from(
        Array(numberOfProofStatements).keys()
      );

      //Reveal the statements indicated from the reveal document
      const documentRevealIndices = revealDocumentStatements.map(
        key =>
          transformedInputDocumentStatements.indexOf(key) +
          numberOfProofStatements
      );

      // Check there is not a mismatch
      if (documentRevealIndices.length !== revealDocumentStatements.length) {
        throw new Error(
          "Some statements in the reveal document not found in original proof"
        );
      }

      // Combine all indices to get the resulting list of revealed indices
      const revealIndices = proofRevealIndices.concat(documentRevealIndices);

      // Create a nonce if one is not supplied
      if (!nonce) {
        nonce = randomBytes(50);
      }

      // Set the nonce on the derived proof
      derivedProof.nonce = Buffer.from(nonce).toString("base64");

      //Combine all the input statements that
      //were originally signed to generate the proof
      const allInputStatements: Uint8Array[] = proofStatements
        .concat(documentStatements)
        .map(item => new Uint8Array(Buffer.from(item)));

      // Fetch the verification method
      const verificationMethod = await this.getVerificationMethod({
        proof,
        document,
        documentLoader,
        expansionMap
      });

      // Construct a key pair class from the returned verification method
      const key = await this.LDKeyClass.from(verificationMethod);

      // Compute the proof
      const outputProof = blsCreateProof({
        signature: new Uint8Array(signature),
        publicKey: new Uint8Array(key.publicKeyBuffer),
        messages: allInputStatements,
        nonce: nonce,
        revealed: revealIndices
      });

      // Set the proof value on the derived proof
      derivedProof.proofValue = Buffer.from(outputProof).toString("base64");

      // Set the relevant proof elements on the derived proof from the input proof
      derivedProof.verificationMethod = proof.verificationMethod;
      derivedProof.proofPurpose = proof.proofPurpose;
      derivedProof.created = proof.created;

      return derivedProof;
    };

    return {
      document: { ...revealDocumentResult },
      proof: await (!Array.isArray(proofs)
        ? derive(proofs)
        : proofs.length > 1
        ? Promise.all(proofs.map(derive))
        : derive(proofs[0]))
    };
  }

  /**
   * @param options {object} options for verifying the proof.
   *
   * @returns {Promise<{object}>} Resolves with the verification result.
   */
  async verifyProof(options: VerifyProofOptions): Promise<VerifyProofResult> {
    const { document, documentLoader, expansionMap, purpose } = options;
    const { proof: proofs } = options;

    const verify = async (proof: any): Promise<VerifyProofResult> => {
      try {
        proof.type = this.supportedDeriveProofType;

        // Get the proof statements
        const proofStatements = await this.createVerifyProofData(proof, {
          documentLoader,
          expansionMap
        });

        // Get the document statements
        const documentStatements = await this.createVerifyProofData(document, {
          documentLoader,
          expansionMap
        });

        // Transform the blank node identifier placeholders for the document statements
        // back into actual blank node identifiers
        const transformedDocumentStatements = documentStatements.map(
          element => {
            const nodeIdentifier = element.split(" ")[0];
            if (nodeIdentifier.startsWith("<urn:bnid:_:c14n")) {
              return element.replace(
                nodeIdentifier,
                nodeIdentifier.substring(
                  "<urn:bnid:".length,
                  nodeIdentifier.length - 1
                )
              );
            }
            return element;
          }
        );

        // Combine all the statements to be verified
        const statementsToVerify: Uint8Array[] = proofStatements
          .concat(transformedDocumentStatements)
          .map(item => new Uint8Array(Buffer.from(item)));

        // Fetch the verification method
        const verificationMethod = await this.getVerificationMethod({
          proof,
          document,
          documentLoader,
          expansionMap
        });

        const key = await this.LDKeyClass.from(verificationMethod);

        // Verify the proof
        const verified = blsVerifyProof({
          proof: new Uint8Array(Buffer.from(proof.proofValue, "base64")),
          publicKey: new Uint8Array(key.publicKeyBuffer),
          messages: statementsToVerify,
          nonce: new Uint8Array(Buffer.from(proof.nonce as string, "base64"))
        });

        // Ensure proof was performed for a valid purpose
        const { valid, error } = await purpose.validate(proof, {
          document,
          suite: this,
          verificationMethod,
          documentLoader,
          expansionMap
        });
        if (!valid) {
          throw error;
        }

        return verified;
      } catch (error) {
        return { verified: false, error };
      }
    };

    if (!Array.isArray(proofs)) {
      return verify(proofs);
    } else {
      const checks = await Promise.all(proofs.map(verify));
      const valid = checks.every(p => p.verified);
      if (valid) {
        return { verified: true };
      } else {
        return {
          verified: false,
          error: checks
            .map(c => c.error)
            .filter(err => !!err)
            .join(", ")
        };
      }
    }
  }

  async canonize(input: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader, expansionMap, skipExpansion } = options;
    return jsonld.canonize(input, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader,
      expansionMap,
      skipExpansion,
      useNative: this.useNativeCanonize
    });
  }

  async canonizeProof(proof: any, options: CanonizeOptions): Promise<string> {
    const { documentLoader, expansionMap } = options;
    proof = { ...proof };

    delete proof.nonce;
    delete proof.proofValue;

    return this.canonize(proof, {
      documentLoader,
      expansionMap,
      skipExpansion: false
    });
  }

  /**
   * @param document {CreateVerifyDataOptions} options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyData(options: CreateVerifyDataOptions): Promise<string[]> {
    const { proof, document, documentLoader, expansionMap } = options;

    const proofStatements = await this.createVerifyProofData(proof, {
      documentLoader,
      expansionMap
    });
    const documentStatements = await this.createVerifyDocumentData(document, {
      documentLoader,
      expansionMap
    });

    // concatenate c14n proof options and c14n document
    return proofStatements.concat(documentStatements);
  }

  /**
   * @param proof to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyProofData(
    proof: any,
    { documentLoader, expansionMap }: any
  ): Promise<string[]> {
    const c14nProofOptions = await this.canonizeProof(proof, {
      documentLoader,
      expansionMap
    });

    return c14nProofOptions.split("\n").filter(_ => _.length > 0);
  }

  /**
   * @param document to canonicalize
   * @param options to create verify data
   *
   * @returns {Promise<{string[]>}.
   */
  async createVerifyDocumentData(
    document: any,
    { documentLoader, expansionMap }: any
  ): Promise<string[]> {
    const c14nDocument = await this.canonize(document, {
      documentLoader,
      expansionMap
    });

    return c14nDocument.split("\n").filter(_ => _.length > 0);
  }

  /**
   * @param document {object} to be signed.
   * @param proof {object}
   * @param documentLoader {function}
   * @param expansionMap {function}
   */
  async getVerificationMethod({ proof, documentLoader }: any): Promise<object> {
    let { verificationMethod } = proof;

    if (typeof verificationMethod === "object") {
      verificationMethod = verificationMethod.id;
    }
    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    // Note: `expansionMap` is intentionally not passed; we can safely drop
    // properties here and must allow for it
    const result = await jsonld.frame(
      verificationMethod,
      {
        "@context": SECURITY_CONTEXT_URL,
        "@embed": "@always",
        id: verificationMethod
      },
      {
        documentLoader,
        compactToRelative: false,
        expandContext: SECURITY_CONTEXT_URL
      }
    );
    if (!result) {
      throw new Error(`Verification method ${verificationMethod} not found.`);
    }

    // ensure verification method has not been revoked
    if (result.revoked !== undefined) {
      throw new Error("The verification method has been revoked.");
    }

    return result;
  }
}
