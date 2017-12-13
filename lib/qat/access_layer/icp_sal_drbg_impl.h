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

/**
 *****************************************************************************
 * @file icp_sal_drbg_impl.h
 *
 * @defgroup icp_sal
 *
 * @ingroup icp_sal
 *
 * @description
 *      This file contains definitions of datatypes and declaration of
 *      functions required to set up the DRBG implementation
 *
 *****************************************************************************/
#ifndef ICP_SAL_DRBG_IMPL_H
#define ICP_SAL_DRBG_IMPL_H

/**
*******************************************************************************
 * @ingroup LacSym
 *      Op Data structure for 'Get Entropy Input' and 'Get Nonce' functions
 * @description
 *      This structure stores information about nonce / entropy input
 *      parameters that are requested from 'Get Entropy Input' and 'Get Nonce'
 *      functions, as suggested NIST SP 800-90, section 9
 *****************************************************************************/
typedef struct icp_sal_drbg_get_entropy_op_data_s{
    CpaCyDrbgSessionHandle sessionHandle;
    /**< Handle to DRBG session for which entropy/nonce is being obtained */
    Cpa32U minEntropy;
    /**< Minimum number of entropy bits requested */
    Cpa32U minLength;
    /**< Minimum length of entropy requested, in bytes */
    Cpa32U maxLength;
    /**< Maximum length of entropy requested, in bytes */
}icp_sal_drbg_get_entropy_op_data_t;

/**
 *****************************************************************************
 * @ingroup LacSym
 *      Definition of a callback function for 'Get Entropy Input' operation.
 *
 * @description
 *      This data structure specifies the prototype for a callback
 *      function for 'Get Entropy Input' operation.
 *
 * @context
 *      This callback function can be executed in a context that DOES NOT
 *      permit sleeping to occur.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in] pCallbackTag Opaque value provided by user while making individual
 *                         function call.
 * @param[in] status       Status of the operation. Valid values are
 *                         CPA_STATUS_SUCCESS and CPA_STATUS_FAIL.
 * @param[in] pOpData      Opaque Pointer to the operation data that was
 *                         submitted in the request.
 * @param[in] lenReturned  Length of entropy returned by 'Get Entropy Input'
 *                         function.
 * @param[in] pOut         Pointer to the output buffer provided in the request
 *                         invoking this callback.
 *
 * @retval
 *      None
 * @pre
 *      None
 * @post
 *      None
 * @note
 *      None
 * @see
 *      None
 *
 *****************************************************************************/
typedef void (*IcpSalDrbgGetEntropyInputCbFunc)(void *pCallbackTag,
        CpaStatus status,
        void *pOpdata,
        Cpa32U lenReturned,
        CpaFlatBuffer *pOut);

/**
*******************************************************************************
 * @ingroup LacSym
 *      Data type for 'Get Entropy Input' function
 * @description
 *      This defines a prototype for user provided 'Get Entropy Input'
 *      function. This function may run either synchronously or
 *      asynchronously
 *
 * @param[in]  pCb              Callback that is to be called to notify that
 *                              entropy input is ready when operating in
 *                              asynchronous mode; if NULL then this is a
 *                              synchronous request and the entropy input
 *                              should be available upon returning from this
 *                              function
 * @param[in]  pCallbackTag     Opaque pointer to user data that is not to be
 *                              changed internally
 * @param[in]  pOpData          Pointer to Op Data structure defining
 *                              parameters of entropy input requested.
 *                              If function cannot meet all the requirements
 *                              as for minimum entropy and its minimum and
 *                              maximum lengths it should return
 *                              CPA_STATUS_FAIL.
 * @param[in]  pBuffer          Pointer to a Flat Buffer where requested
 *                              entropy input is to be stored; this buffer is
 *                              supposed to store at least maxLength bytes
 *                              as indicated in Op Data structure
 * @param[out] pLengthReturned  Pointer to a Cpa32U variable in which the
 *                              actual length of returned entropy input is
 *                              given. The length is given in bytes. This is
 *                              supposed to be returned only if function is
 *                              called in synchronous mode (when pCb parameter
 *                              is set to NULL).
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
 *      This function is synchronous and blocking.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @return CPA_STATUS_SUCCESS         Operation successful
 * @return CPA_STATUS_INVALID_PARAM   Invalid param provided
 * @return CPA_STATUS_FAIL            Operation failed or entropy requirements
 *                                    specified by pOpData cannot be met.
 *
 *****************************************************************************/
typedef CpaStatus (*IcpSalDrbgGetEntropyInputFunc)(
        IcpSalDrbgGetEntropyInputCbFunc pCb,
        void * pCallbackTag,
        icp_sal_drbg_get_entropy_op_data_t *pOpData,
        CpaFlatBuffer *pBuffer,
        Cpa32U *pLengthReturned);


/**
*******************************************************************************
 * @ingroup LacSym
 *      Data type for 'Get Nonce' function
 * @description
 *      This type defines the prototype that user provided 'Get Nonce'
 *      function must meet. This is a synchronous function
 *
 * @param[in]  pOpData          Pointer to Op Data structure defining
 *                              parameters of nonce requested
 * @param[in]  pBuffer          Pointer to a Flat Buffer where requested
 *                              nonce is to be stored; this buffer is
 *                              supposed to store at least maxLength bytes
 *                              as indicated in Op Data structure
 * @param[out] pLengthReturned  Pointer to a Cpa32U variable where in which
 *                              the actual length of returned nonce is given.
 *                              This is the length in bytes.
 *
 * @context
 *      This is a synchronous function and it may sleep. It MUST NOT be
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
 * @return CPA_STATUS_SUCCESS         Operation successful
 * @return CPA_STATUS_INVALID_PARAM   Invalid param provided
 * @return CPA_STATUS_FAIL            Operation failed
 *
 *****************************************************************************/
typedef CpaStatus (*IcpSalDrbgGetNonceFunc)(
        icp_sal_drbg_get_entropy_op_data_t *pOpData,
        CpaFlatBuffer *pBuffer,
        Cpa32U *pLengthReturned);


/**
*******************************************************************************
 * @ingroup LacSym
 *      Data type for 'Is Derivation Function Required' function
 * @description
 *      This type defines the prototype that user provided 'Is Derivation
 *      Function Required' function must meet. This is a synchronous function
 *
 * @context
 *      This function cannot sleep. It can be executed in a context that
 *      does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @return CPA_TRUE         Entropy input requires derivation function
 *                          to be used
 * @return CPA_FALSE        Entropy input does not require derivation function
 *                          to be used
 *
 *****************************************************************************/
typedef CpaBoolean (*IcpSalDrbgIsDFReqFunc)(void);

/**
*******************************************************************************
 * @ingroup LacSym
 *      Registers 'Get Entropy Input' function
 * @description
 *      This function registers 'Get Entropy Input' function. This function
 *      MUST be called first before any DRBG API function can be called
 *
 * @param[in]   func        'Get Entropy Input' function to be registered
 *
 * @context
 *      This function cannot sleep. It can be executed in a context that
 *      does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @return Previously set function or NULL if none
 *
 *****************************************************************************/
IcpSalDrbgGetEntropyInputFunc
icp_sal_drbgGetEntropyInputFuncRegister(IcpSalDrbgGetEntropyInputFunc func);

/**
*******************************************************************************
 * @ingroup LacSym
 *      Registers 'Get Nonce' function
 * @description
 *      This function registers 'Get Nonce' function. This function
 *      MUST be called first before any DRBG API function can be called
 *
 * @param[in]   func        'Get Nonce' function to be registered
 *
 * @context
 *      This function cannot sleep. It can be executed in a context that
 *      does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @return Previously set function or NULL if none
 *
 *****************************************************************************/
IcpSalDrbgGetNonceFunc
icp_sal_drbgGetNonceFuncRegister(IcpSalDrbgGetNonceFunc func);


/**
*******************************************************************************
 * @ingroup LacSym
 *      Registers 'Is Derivation Function Required' function
 * @description
 *      This function registers 'Is Derivation Function Required' function.
 *      This function MUST be called first before any DRBG API function
 *      can be called
 *
 * @param[in]   func        'Is Derivation Function Required' function to
 *                          be registered
 *
 * @context
 *      This function cannot sleep. It can be executed in a context that
 *      does not permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      No
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @return Previously set function or NULL if none
 *
 *****************************************************************************/
IcpSalDrbgIsDFReqFunc
icp_sal_drbgIsDFReqFuncRegister(IcpSalDrbgIsDFReqFunc func);

/**
 ******************************************************************************
 * @ingroup LacSym_Drbg
 *     Utility function to get the instance Handle that drbg is using
 *
 * @description
 *      This utility function gets the instanceHandle from the sessionHandle
 *
 * @param[in]  sessionHandle       DRBG session Handle
 *                                 structure which contains the session handle
 * @param[out] pDrbgInstance       Pointer to the instanceHandle
 *
 * @return  none
 *
 *****************************************************************************/
void
icp_sal_drbgGetInstance(CpaCyDrbgSessionHandle sessionHandle,
                        CpaInstanceHandle **pDrbgInstance);

#endif /* ICP_SAL_DRBG_IMPL_H */
