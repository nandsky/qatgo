/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or 
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2013 Intel Corporation. All rights reserved.
 * 
 *   This program is free software; you can redistribute it and/or modify 
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful, but 
 *   WITHOUT ANY WARRANTY; without even the implied warranty of 
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
 *   General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License 
 *   along with this program; if not, write to the Free Software 
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution 
 *   in the file called LICENSE.GPL.
 * 
 *   Contact Information:
 *   Intel Corporation
 * 
 *   BSD LICENSE 
 * 
 *   Copyright(c) 2007-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without 
 *   modification, are permitted provided that the following conditions 
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright 
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright 
 *       notice, this list of conditions and the following disclaimer in 
 *       the documentation and/or other materials provided with the 
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its 
 *       contributors may be used to endorse or promote products derived 
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * 
 *  version: QAT1.6.L.2.6.0-65
 *
 ***************************************************************************/

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 *
 * @defgroup cpaCyKeyGen Cryptographic Key and Mask Generation API
 *
 * @ingroup cpaCy
 *
 * @description
 *      These functions specify the API for key and mask generation
 *      operations.
 *
 *****************************************************************************/

#ifndef CPA_CY_KEY_H
#define CPA_CY_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa_cy_common.h"
#include "cpa_cy_sym.h" /* needed for hash algorithm, for MGF */

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      SSL or TLS key generation random number length.
 *
 * @description
 *      Defines the permitted SSL or TLS random number length in bytes that
 *      may be used with the functions @ref cpaCyKeyGenSsl and @ref
 *      cpaCyKeyGenTls.   This is the length of the client or server random
 *      number values.
 *****************************************************************************/
#define CPA_CY_KEY_GEN_SSL_TLS_RANDOM_LEN_IN_BYTES   (32)

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      SSL Operation Types
 * @description
 *      Enumeration of the different SSL operations that can be specified in
 *      the struct @ref CpaCyKeyGenSslOpData.  It identifies the label.
 *****************************************************************************/
typedef enum _CpaCyKeySslOp
{
    CPA_CY_KEY_SSL_OP_MASTER_SECRET_DERIVE = 1,
    /**< Derive the master secret */
    CPA_CY_KEY_SSL_OP_KEY_MATERIAL_DERIVE,
    /**< Derive the key material */
    CPA_CY_KEY_SSL_OP_USER_DEFINED
    /**< User Defined Operation for custom labels*/
} CpaCyKeySslOp;


/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      SSL data for key generation functions
 * @description
 *      This structure contains data for use in key generation operations for
 *      SSL. For specific SSL key generation operations, the structure fields
 *      MUST be set as follows:
 *
 *      @par SSL Master-Secret Derivation:
 *          <br> sslOp = CPA_CY_KEY_SSL_OP_MASTER_SECRET_DERIVE
 *          <br> secret = pre-master secret key
 *          <br> seed = client_random + server_random
 *          <br> userLabel = NULL
 *
 *      @par SSL Key-Material Derivation:
 *          <br> sslOp = CPA_CY_KEY_SSL_OP_KEY_MATERIAL_DERIVE
 *          <br> secret = master secret key
 *          <br> seed = server_random + client_random
 *          <br> userLabel = NULL
 *
 *          <br> Note that the client/server random order is reversed from that
 *          used for master-secret derivation.
 *
 *      @note Each of the client and server random numbers need to be of
 *      length CPA_CY_KEY_GEN_SSL_TLS_RANDOM_LEN_IN_BYTES.
 *
 *      @note In each of the above descriptions, + indicates concatenation.
 *
 *      @note The label used is predetermined by the SSL operation in line
 *      with the SSL 3.0 specification, and can be overridden by using
 *      a user defined operation CPA_CY_KEY_SSL_OP_USER_DEFINED and
 *      associated userLabel.
 *
 ****************************************************************************/
typedef struct _CpaCyKeyGenSslOpData {
    CpaCyKeySslOp sslOp;
    /**< Indicate the SSL operation to be performed */
    CpaFlatBuffer secret;
    /**<  Flat buffer containing a pointer to either the master or pre-master
     * secret key. The length field indicates the length of the secret key in
     * bytes. Implementation-specific limits may apply to this length. */
    CpaFlatBuffer seed;
    /**<  Flat buffer containing a pointer to the seed data.
     * Implementation-specific limits may apply to this length. */
    Cpa32U generatedKeyLenInBytes;
    /**< The requested length of the generated key in bytes.
     * Implementation-specific limits may apply to this length. */
    CpaFlatBuffer userLabel;
    /**<  Optional flat buffer containing a pointer to a user defined label.
     * The length field indicates the length of the label in bytes. To use this
     * field, the sslOp must be CPA_CY_KEY_SSL_OP_USER_DEFINED, otherwise
     * it is ignored and can be set to NULL.  Implementation-specific limits
     * may apply to this length. */
} CpaCyKeyGenSslOpData;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      TLS Operation Types
 * @description
 *      Enumeration of the different TLS operations that can be specified in
 *      the CpaCyKeyGenTlsOpData.  It identifies the label.
 *
 *      The functions @ref cpaCyKeyGenTls and @ref cpaCyKeyGenTls2
 *      accelerate the TLS PRF, which is defined as part of RFC2246 (TLS
 *      v1.0), RFC4346 (TLS v1.1), and RFC5246 (TLS v1.2).  One of the
 *      inputs to these functions is a label. This enumerated type defines
 *      values that correspond to some of the required labels.
 *      However, for some of the operations/labels required by these RFCs,
 *      no values are specified.
 *
 *      In such cases, a user-defined value must be provided.  The client
 *      should use the enum value @ref CPA_CY_KEY_TLS_OP_USER_DEFINED, and
 *      pass the label using the userLabel field of the @ref
 *      CpaCyKeyGenTlsOpData data structure.
 *
 *****************************************************************************/
typedef enum _CpaCyKeyTlsOp
{
    CPA_CY_KEY_TLS_OP_MASTER_SECRET_DERIVE = 1,
    /**< Derive the master secret using the TLS PRF.
     * Corresponds to RFC2246/5246 section 8.1, operation "Computing the
     * master secret", label "master secret". */
    CPA_CY_KEY_TLS_OP_KEY_MATERIAL_DERIVE,
    /**< Derive the key material using the TLS PRF.
     * Corresponds to RFC2246/5246 section 6.3, operation "Derive the key
     * material", label "key expansion". */
    CPA_CY_KEY_TLS_OP_CLIENT_FINISHED_DERIVE,
    /**< Derive the client finished tag using the TLS PRF.
     * Corresponds to RFC2246/5246 section 7.4.9, operation "Client finished",
     * label "client finished". */
    CPA_CY_KEY_TLS_OP_SERVER_FINISHED_DERIVE,
    /**< Derive the server finished tag using the TLS PRF.
     * Corresponds to RFC2246/5246 section 7.4.9, operation "Server finished",
     * label "server finished". */
    CPA_CY_KEY_TLS_OP_USER_DEFINED
    /**< User Defined Operation for custom labels. */
} CpaCyKeyTlsOp;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      TLS data for key generation functions
 * @description
 *      This structure contains data for use in key generation operations for
 *      TLS. For specific TLS key generation operations, the structure fields
 *      MUST be set as follows:
 *
 *      @par TLS Master-Secret Derivation:
 *          <br> tlsOp = CPA_CY_KEY_TLS_OP_MASTER_SECRET_DERIVE
 *          <br> secret = pre-master secret key
 *          <br> seed = client_random + server_random
 *          <br> userLabel = NULL
 *
 *      @par TLS Key-Material Derivation:
 *          <br> tlsOp = CPA_CY_KEY_TLS_OP_KEY_MATERIAL_DERIVE
 *          <br> secret = master secret key
 *          <br> seed = server_random + client_random
 *          <br> userLabel = NULL
 *
 *          <br> Note that the client/server random order is reversed from
 *          that used for Master-Secret Derivation.
 *
 *      @par TLS Client finished/Server finished tag Derivation:
 *          <br> tlsOp = CPA_CY_KEY_TLS_OP_CLIENT_FINISHED_DERIVE  (client)
 *          <br>      or CPA_CY_KEY_TLS_OP_SERVER_FINISHED_DERIVE  (server)
 *          <br> secret = master secret key
 *          <br> seed = MD5(handshake_messages) + SHA-1(handshake_messages)
 *          <br> userLabel = NULL
 *
 *      @note Each of the client and server random seeds need to be of
 *      length CPA_CY_KEY_GEN_SSL_TLS_RANDOM_LEN_IN_BYTES.
 *      @note In each of the above descriptions, + indicates concatenation.
 *      @note The label used is predetermined by the TLS operation in line
 *      with the TLS specifications, and can be overridden by using
 *      a user defined operation CPA_CY_KEY_TLS_OP_USER_DEFINED
 *      and associated userLabel.
 *
 ****************************************************************************/
typedef struct _CpaCyKeyGenTlsOpData {
    CpaCyKeyTlsOp tlsOp;
    /**< TLS operation to be performed */
    CpaFlatBuffer secret;
    /**< Flat buffer containing a pointer to either the master or pre-master
     * secret key. The length field indicates the length of the secret in
     * bytes. Implementation-specific limits may apply to this length. */
    CpaFlatBuffer seed;
    /**< Flat buffer containing a pointer to the seed data.
     * Implementation-specific limits may apply to this length. */
    Cpa32U generatedKeyLenInBytes;
    /**< The requested length of the generated key in bytes.
     * Implementation-specific limits may apply to this length. */
    CpaFlatBuffer userLabel;
    /**< Optional flat buffer containing a pointer to a user defined label.
     * The length field indicates the length of the label in bytes. To use this
     * field, the tlsOp must be CPA_CY_KEY_TLS_OP_USER_DEFINED, otherwise
     * it is ignored and can be set to NULL. Implementation-specific limits
     * may apply to this length. */
} CpaCyKeyGenTlsOpData;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Key Generation Mask Generation Function (MGF) Data
 * @description
 *      This structure contains data relating to Mask Generation Function
 *      key generation operations.
 *
 *      @note The default hash algorithm used by the MGF is SHA-1.  If a
 *      different hash algorithm is preferred, then see the extended
 *      version of this structure, @ref CpaCyKeyGenMgfOpDataExt.
 * @see
 *        cpaCyKeyGenMgf
 ****************************************************************************/
typedef struct _CpaCyKeyGenMgfOpData {
    CpaFlatBuffer seedBuffer;
    /**<  Caller MUST allocate a buffer and populate with the input seed
     * data. For optimal performance the start of the seed SHOULD be allocated
     * on an 8-byte boundary. The length field represents the seed length in
     * bytes.  Implementation-specific limits may apply to this length. */
    Cpa32U maskLenInBytes;
    /**< The requested length of the generated mask in bytes.
     * Implementation-specific limits may apply to this length. */
} CpaCyKeyGenMgfOpData;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Extension to the original Key Generation Mask Generation Function
 *      (MGF) Data
 * @description
 *      This structure is an extension to the original MGF data structure.
 *      The extension allows the hash function to be specified.
 * @note
 *      This structure is separate from the base @ref CpaCyKeyGenMgfOpData
 *      structure in order to retain backwards compatibility with the
 *      original version of the API.
 * @see
 *        cpaCyKeyGenMgfExt
 ****************************************************************************/
typedef struct _CpaCyKeyGenMgfOpDataExt {
    CpaCyKeyGenMgfOpData baseOpData;
    /**<  "Base" operational data for MGF generation */
    CpaCySymHashAlgorithm hashAlgorithm;
    /**< Specifies the hash algorithm to be used by the Mask Generation
     * Function */
} CpaCyKeyGenMgfOpDataExt;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Key Generation Statistics.
 * @deprecated
 *      As of v1.3 of the Crypto API, this structure has been deprecated,
 *      replaced by @ref CpaCyKeyGenStats64.
 * @description
 *      This structure contains statistics on the key and mask generation
 *      operations. Statistics are set to zero when the component is
 *      initialized, and are collected per instance.
 *
 ****************************************************************************/
typedef struct _CpaCyKeyGenStats {
    Cpa32U numSslKeyGenRequests;
    /**< Total number of successful SSL key generation requests. */
    Cpa32U numSslKeyGenRequestErrors;
    /**< Total number of SSL key generation requests that had an error and
     *   could not be processed. */
    Cpa32U numSslKeyGenCompleted;
    /**< Total number of SSL key generation operations that completed
     *   successfully. */
    Cpa32U numSslKeyGenCompletedErrors;
    /**< Total number of SSL key generation operations that could not be
     *   completed successfully due to errors. */
    Cpa32U numTlsKeyGenRequests;
    /**< Total number of successful TLS key generation requests. */
    Cpa32U numTlsKeyGenRequestErrors;
    /**< Total number of TLS key generation requests that had an error and
     *   could not be processed. */
    Cpa32U numTlsKeyGenCompleted;
    /**< Total number of TLS key generation operations that completed
     *   successfully. */
    Cpa32U numTlsKeyGenCompletedErrors;
    /**< Total number of TLS key generation operations that could not be
     *   completed successfully due to errors. */
    Cpa32U numMgfKeyGenRequests;
    /**< Total number of successful MGF key generation requests (including
     *   "extended" MGF requests). */
    Cpa32U numMgfKeyGenRequestErrors;
    /**< Total number of MGF key generation requests that had an error and
     *   could not be processed. */
    Cpa32U numMgfKeyGenCompleted;
    /**< Total number of MGF key generation operations that completed
     *   successfully. */
    Cpa32U numMgfKeyGenCompletedErrors;
    /**< Total number of MGF key generation operations that could not be
     *   completed successfully due to errors. */
} CpaCyKeyGenStats CPA_DEPRECATED;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Key Generation Statistics (64-bit version).
 * @description
 *      This structure contains the 64-bit version of the statistics
 *      on the key and mask generation operations.
 *      Statistics are set to zero when the component is
 *      initialized, and are collected per instance.
 *
 ****************************************************************************/
typedef struct _CpaCyKeyGenStats64 {
    Cpa64U numSslKeyGenRequests;
    /**< Total number of successful SSL key generation requests. */
    Cpa64U numSslKeyGenRequestErrors;
    /**< Total number of SSL key generation requests that had an error and
     *   could not be processed. */
    Cpa64U numSslKeyGenCompleted;
    /**< Total number of SSL key generation operations that completed
     *   successfully. */
    Cpa64U numSslKeyGenCompletedErrors;
    /**< Total number of SSL key generation operations that could not be
     *   completed successfully due to errors. */
    Cpa64U numTlsKeyGenRequests;
    /**< Total number of successful TLS key generation requests. */
    Cpa64U numTlsKeyGenRequestErrors;
    /**< Total number of TLS key generation requests that had an error and
     *   could not be processed. */
    Cpa64U numTlsKeyGenCompleted;
    /**< Total number of TLS key generation operations that completed
     *   successfully. */
    Cpa64U numTlsKeyGenCompletedErrors;
    /**< Total number of TLS key generation operations that could not be
     *   completed successfully due to errors. */
    Cpa64U numMgfKeyGenRequests;
    /**< Total number of successful MGF key generation requests (including
     *   "extended" MGF requests). */
    Cpa64U numMgfKeyGenRequestErrors;
    /**< Total number of MGF key generation requests that had an error and
     *   could not be processed. */
    Cpa64U numMgfKeyGenCompleted;
    /**< Total number of MGF key generation operations that completed
     *   successfully. */
    Cpa64U numMgfKeyGenCompletedErrors;
    /**< Total number of MGF key generation operations that could not be
     *   completed successfully due to errors. */
} CpaCyKeyGenStats64;

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      SSL Key Generation Function.
 * @description
 *      This function is used for SSL key generation.  It implements the key
 *      generation function defined in section 6.2.2 of the SSL 3.0
 *      specification as described in
 *      http://www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt.
 *
 *      The input seed is taken as a flat buffer and the generated key is
 *      returned to caller in a flat destination data buffer.
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] instanceHandle             Instance handle.
 * @param[in] pKeyGenCb                  Pointer to callback function to be
 *                                       invoked when the operation is complete.
 *                                       If this is set to a NULL value the
 *                                       function will operate synchronously.
 * @param[in] pCallbackTag               Opaque User Data for this specific
 *                                       call. Will be returned unchanged in the
 *                                       callback.
 * @param[in] pKeyGenSslOpData           Structure containing all the data
 *                                       needed to perform the SSL key
 *                                       generation operation. The client code
 *                                       allocates the memory for this
 *                                       structure. This component takes
 *                                       ownership of the memory until it is
 *                                       returned in the callback.
 * @param[out] pGeneratedKeyBuffer       Caller MUST allocate a sufficient
 *                                       buffer to hold the key generation
 *                                       output. The data pointer SHOULD be
 *                                       aligned on an 8-byte boundary. The
 *                                       length field passed in represents the
 *                                       size of the buffer in bytes. The value
 *                                       that is returned is the size of the
 *                                       result key in bytes.
 *                                       On invocation the callback function
 *                                       will contain this parameter in the
 *                                       pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS            Function executed successfully.
 * @retval CPA_STATUS_FAIL               Function failed.
 * @retval CPA_STATUS_RETRY              Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM      Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE           Error related to system resources.
 * @retval CPA_STATUS_RESTARTING         API implementation is restarting.
 *                                       Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED        Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @see
 *      CpaCyKeyGenSslOpData,
 *      CpaCyGenFlatBufCbFunc
 *
 *****************************************************************************/
CpaStatus
cpaCyKeyGenSsl(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pKeyGenCb,
        void *pCallbackTag,
        const CpaCyKeyGenSslOpData *pKeyGenSslOpData,
        CpaFlatBuffer *pGeneratedKeyBuffer);

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      TLS Key Generation Function.
 * @description
 *      This function is used for TLS key generation.  It implements the
 *      TLS PRF (Pseudo Random Function) as defined by RFC2246 (TLS v1.0)
 *      and RFC4346 (TLS v1.1).
 *
 *      The input seed is taken as a flat buffer and the generated key is
 *      returned to caller in a flat destination data buffer.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle            Instance handle.
 * @param[in]  pKeyGenCb                 Pointer to callback function to be
 *                                       invoked when the operation is complete.
 *                                       If this is set to a NULL value the
 *                                       function will operate synchronously.
 * @param[in]  pCallbackTag              Opaque User Data for this specific
 *                                       call. Will be returned unchanged in the
 *                                       callback.
 * @param[in]  pKeyGenTlsOpData          Structure containing all the data
 *                                       needed to perform the TLS key
 *                                       generation operation. The client code
 *                                       allocates the memory for this
 *                                       structure. This component takes
 *                                       ownership of the memory until it is
 *                                       returned in the callback.
 * @param[out] pGeneratedKeyBuffer       Caller MUST allocate a sufficient
 *                                       buffer to hold the key generation
 *                                       output. The data pointer SHOULD be
 *                                       aligned on an 8-byte boundary. The
 *                                       length field passed in represents the
 *                                       size of the buffer in bytes. The value
 *                                       that is returned is the size of the
 *                                       result key in bytes.
 *                                       On invocation the callback function
 *                                       will contain this parameter in the
 *                                       pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS            Function executed successfully.
 * @retval CPA_STATUS_FAIL               Function failed.
 * @retval CPA_STATUS_RETRY              Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM      Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE           Error related to system resources.
 * @retval CPA_STATUS_RESTARTING         API implementation is restarting.
 *                                       Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED        Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @see
 *      CpaCyKeyGenTlsOpData,
 *      CpaCyGenFlatBufCbFunc
 *
 *****************************************************************************/
CpaStatus
cpaCyKeyGenTls(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pKeyGenCb,
        void *pCallbackTag,
        const CpaCyKeyGenTlsOpData *pKeyGenTlsOpData,
        CpaFlatBuffer *pGeneratedKeyBuffer);

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      TLS Key Generation Function version 2.
 * @description
 *      This function is used for TLS key generation.  It implements the
 *      TLS PRF (Pseudo Random Function) as defined by RFC5246 (TLS v1.2).
 *
 *      The input seed is taken as a flat buffer and the generated key is
 *      returned to caller in a flat destination data buffer.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle            Instance handle.
 * @param[in]  pKeyGenCb                 Pointer to callback function to be
 *                                       invoked when the operation is complete.
 *                                       If this is set to a NULL value the
 *                                       function will operate synchronously.
 * @param[in]  pCallbackTag              Opaque User Data for this specific
 *                                       call. Will be returned unchanged in the
 *                                       callback.
 * @param[in]  pKeyGenTlsOpData          Structure containing all the data
 *                                       needed to perform the TLS key
 *                                       generation operation. The client code
 *                                       allocates the memory for this
 *                                       structure. This component takes
 *                                       ownership of the memory until it is
 *                                       returned in the callback.
 * @param[in]  hashAlgorithm             Specifies the hash algorithm to use.
 *                                       According to RFC5246, this should be
 *                                       "SHA-256 or a stronger standard hash
 *                                       function."
 * @param[out] pGeneratedKeyBuffer       Caller MUST allocate a sufficient
 *                                       buffer to hold the key generation
 *                                       output. The data pointer SHOULD be
 *                                       aligned on an 8-byte boundary. The
 *                                       length field passed in represents the
 *                                       size of the buffer in bytes. The value
 *                                       that is returned is the size of the
 *                                       result key in bytes.
 *                                       On invocation the callback function
 *                                       will contain this parameter in the
 *                                       pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS            Function executed successfully.
 * @retval CPA_STATUS_FAIL               Function failed.
 * @retval CPA_STATUS_RETRY              Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM      Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE           Error related to system resources.
 * @retval CPA_STATUS_RESTARTING         API implementation is restarting.
 *                                       Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED        Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @see
 *      CpaCyKeyGenTlsOpData,
 *      CpaCyGenFlatBufCbFunc
 *
 *****************************************************************************/
CpaStatus
cpaCyKeyGenTls2(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pKeyGenCb,
        void *pCallbackTag,
        const CpaCyKeyGenTlsOpData *pKeyGenTlsOpData,
        CpaCySymHashAlgorithm hashAlgorithm,
        CpaFlatBuffer *pGeneratedKeyBuffer);

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Mask Generation Function.
 * @description
 *      This function implements the mask generation function MGF1 as
 *      defined by PKCS#1 v2.1, and RFC3447.  The input seed is taken
 *      as a flat buffer and the generated mask is returned to caller in a
 *      flat destination data buffer.
 *
 *      @note The default hash algorithm used by the MGF is SHA-1.  If a
 *      different hash algorithm is preferred, then see the "extended"
 *      version of this function, @ref cpaCyKeyGenMgfExt.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  pKeyGenCb             Pointer to callback function to be
 *                                   invoked when the operation is complete.
 *                                   If this is set to a NULL value the
 *                                   function will operate synchronously.
 * @param[in]  pCallbackTag          Opaque User Data for this specific call.
 *                                   Will be returned unchanged in the
 *                                   callback.
 * @param[in]  pKeyGenMgfOpData      Structure containing all the data needed
 *                                   to perform the MGF key generation
 *                                   operation. The client code allocates the
 *                                   memory for this structure. This
 *                                   component takes ownership of the memory
 *                                   until it is returned in the callback.
 * @param[out] pGeneratedMaskBuffer  Caller MUST allocate a sufficient buffer
 *                                   to hold the generated mask. The data
 *                                   pointer SHOULD be aligned on an 8-byte
 *                                   boundary. The length field passed in
 *                                   represents the size of the buffer in
 *                                   bytes. The value that is returned is the
 *                                   size of the generated mask in bytes.
 *                                   On invocation the callback function
 *                                   will contain this parameter in the
 *                                   pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully.
 * @retval CPA_STATUS_FAIL              Function failed.
 * @retval CPA_STATUS_RETRY             Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM     Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE          Error related to system resources.
 * @retval CPA_STATUS_RESTARTING        API implementation is restarting.
 *                                      Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED       Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @see
 *      CpaCyKeyGenMgfOpData,
 *      CpaCyGenFlatBufCbFunc
 *
 *****************************************************************************/
CpaStatus
cpaCyKeyGenMgf(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pKeyGenCb,
        void *pCallbackTag,
        const CpaCyKeyGenMgfOpData *pKeyGenMgfOpData,
        CpaFlatBuffer *pGeneratedMaskBuffer);

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Extended Mask Generation Function.
 * @description
 *      This function is used for mask generation. It differs from the "base"
 *      version of the function (@ref cpaCyKeyGenMgf) in that it allows
 *      the hash function used by the Mask Generation Function to be
 *      specified.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  pKeyGenCb             Pointer to callback function to be
 *                                   invoked when the operation is complete.
 *                                   If this is set to a NULL value the
 *                                   function will operate synchronously.
 * @param[in]  pCallbackTag          Opaque User Data for this specific call.
 *                                   Will be returned unchanged in the
 *                                   callback.
 * @param[in]  pKeyGenMgfOpDataExt   Structure containing all the data needed
 *                                   to perform the extended MGF key generation
 *                                   operation. The client code allocates the
 *                                   memory for this structure. This
 *                                   component takes ownership of the memory
 *                                   until it is returned in the callback.
 * @param[out] pGeneratedMaskBuffer  Caller MUST allocate a sufficient buffer
 *                                   to hold the generated mask. The data
 *                                   pointer SHOULD be aligned on an 8-byte
 *                                   boundary. The length field passed in
 *                                   represents the size of the buffer in
 *                                   bytes. The value that is returned is the
 *                                   size of the generated mask in bytes.
 *                                   On invocation the callback function
 *                                   will contain this parameter in the
 *                                   pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS           Function executed successfully.
 * @retval CPA_STATUS_FAIL              Function failed.
 * @retval CPA_STATUS_RETRY             Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM     Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE          Error related to system resources.
 * @retval CPA_STATUS_RESTARTING        API implementation is restarting.
 *                                      Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED       Function is not supported.
 *
 * @pre
 *      The component has been initialized via cpaCyStartInstance function.
 * @post
 *      None
 * @note
 *      This function is only used to generate a mask keys from seed
 *      material.
 * @see
 *      CpaCyKeyGenMgfOpData,
 *      CpaCyGenFlatBufCbFunc
 *
 *****************************************************************************/
CpaStatus
cpaCyKeyGenMgfExt(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pKeyGenCb,
        void *pCallbackTag,
        const CpaCyKeyGenMgfOpDataExt *pKeyGenMgfOpDataExt,
        CpaFlatBuffer *pGeneratedMaskBuffer);

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Queries the Key and Mask generation statistics specific to
 *      an instance.
 *
 * @deprecated
 *      As of v1.3 of the Crypto API, this function has been deprecated,
 *      replaced by @ref cpaCyKeyGenQueryStats64().
 *
 * @description
 *      This function will query a specific instance for key and mask
 *      generation statistics. The user MUST allocate the CpaCyKeyGenStats
 *      structure and pass the reference to that into this function call. This
 *      function will write the statistic results into the passed in
 *      CpaCyKeyGenStats structure.
 *
 *      Note: statistics returned by this function do not interrupt current data
 *      processing and as such can be slightly out of sync with operations that
 *      are in progress during the statistics retrieval process.
 *
 * @context
 *      This is a synchronous function and it can sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle       Instance handle.
 * @param[out] pKeyGenStats         Pointer to memory into which the statistics
 *                                  will be written.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting.
 *                                   Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 * @note
 *      This function operates in a synchronous manner and no asynchronous
 *      callback will be generated.
 *
 * @see
 *      CpaCyKeyGenStats
 *
 *****************************************************************************/
CpaStatus CPA_DEPRECATED
cpaCyKeyGenQueryStats(const CpaInstanceHandle instanceHandle,
        struct _CpaCyKeyGenStats *pKeyGenStats);

/**
 *****************************************************************************
 * @file cpa_cy_key.h
 * @ingroup cpaCyKeyGen
 *      Queries the Key and Mask generation statistics (64-bit version)
 *      specific to an instance.
 *
 * @description
 *      This function will query a specific instance for key and mask
 *      generation statistics. The user MUST allocate the CpaCyKeyGenStats64
 *      structure and pass the reference to that into this function call. This
 *      function will write the statistic results into the passed in
 *      CpaCyKeyGenStats64 structure.
 *
 *      Note: statistics returned by this function do not interrupt current data
 *      processing and as such can be slightly out of sync with operations that
 *      are in progress during the statistics retrieval process.
 *
 * @context
 *      This is a synchronous function and it can sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle       Instance handle.
 * @param[out] pKeyGenStats         Pointer to memory into which the statistics
 *                                  will be written.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully.
 * @retval CPA_STATUS_FAIL           Function failed.
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE       Error related to system resources.
 * @retval CPA_STATUS_RESTARTING     API implementation is restarting.
 *                                   Resubmit the request.
 * @retval CPA_STATUS_UNSUPPORTED    Function is not supported.
 *
 * @pre
 *      Component has been initialized.
 * @post
 *      None
 * @note
 *      This function operates in a synchronous manner and no asynchronous
 *      callback will be generated.
 *
 * @see
 *      CpaCyKeyGenStats64
 *****************************************************************************/
CpaStatus
cpaCyKeyGenQueryStats64(const CpaInstanceHandle instanceHandle,
        CpaCyKeyGenStats64 *pKeyGenStats);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_CY_KEY_H */
