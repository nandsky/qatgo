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
 * @file icp_sal_drbg_ht.h
 *
 * @ingroup icp_sal
 *
 * @description
 *      This file contains declarations of functions used to test DRBG
 *      implementation for health
 *
 *****************************************************************************/
#ifndef ICP_SAL_DRBG_HT_H
#define ICP_SAL_DRBG_HT_H

/**
 *****************************************************************************
 * @ingroup icp_sal
 *      Handle to a DRBG Health Test session
 *
 * @description
 *      This is a handle to DRBG test session used by DRBG health test
 *      functions: @ref icp_sal_drbgHTInstantiate, @ref icp_sal_drbgHTGenerate
 *      and @ref icp_sal_drbgHTReseed. The memory for this handle is allocated
 *      by the client. The size of the memory that the client needs to
 *      allocate is determined by a call to the
 *      @ref icp_sal_drbgHTGetTestSessionSize function.
 *
 *****************************************************************************/
typedef void* IcpSalDrbgTestSessionHandle;

/**
 ******************************************************************************
 * @ingroup LacSym
 *      Gets the size of DRBG health test session
 * @description
 *      This function returns size of the contiguous memory that needs to be
 *      allocated by the user for the DRBG health test session
 *
 * @context
 *      Might be executed in a context that DOES NOT permit sleeping.
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
 * @param[in]   instanceHandle   Handle of instance for which DRBG is to be
 *                               tested
 * @param[out]  pTestSessionSize Pointer to a variable to store size of the
 *                               memory required for DRBG health test session
 *
 * @return CPA_STATUS_SUCCESS    Operation successful
 * @return CPA_STATUS_FAIL       Operation failed
 *
 *****************************************************************************/
CpaStatus
icp_sal_drbgHTGetTestSessionSize(CpaInstanceHandle instanceHandle,
                                 Cpa32U *pTestSessionSize);

/**
 ******************************************************************************
 * @ingroup LacSym
 *      Tests health of Instantiate function
 * @description
 *      This function tests health of Instantiate functionality as described
 *      in NIST SP 800-90, section 11.3.2. This function tests Instantiate
 *      for all possible setup configurations.
 *
 * @context
 *      MUST NOT be executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]   instanceHandle    Handle of instance for which DRBG is to be
 *                                tested
 * @param[in]   testSessionHandle Handle of DRBG health test session.
 *                                Physically contiguous memory for this session
 *                                should be allocated by the user.
 *
 * @return CPA_STATUS_SUCCESS    Health tests passed
 * @return CPA_STATUS_FAIL       Health tests failed
 *
 *****************************************************************************/
CpaStatus
icp_sal_drbgHTInstantiate(const CpaInstanceHandle instanceHandle,
                            IcpSalDrbgTestSessionHandle testSessionHandle);

/**
 ******************************************************************************
 * @ingroup LacSym
 *      Tests health of Generate function
 * @description
 *      This function tests health of Generate function as described
 *      in NIST SP 800-90, section 11.3.3
 *
 * @context
 *      MUST NOT be executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]   instanceHandle    Handle of instance for which DRBG is to be
 *                                tested
 * @param[in]   testSessionHandle Handle of DRBG health test session.
 *                                Physically contiguous memory for this
 *                                session should be allocated by the user.
 *
 * @return CPA_STATUS_SUCCESS    Health tests passed
 * @return CPA_STATUS_FAIL       Health tests failed
 *
 *****************************************************************************/
CpaStatus
icp_sal_drbgHTGenerate(const CpaInstanceHandle instanceHandle,
                        IcpSalDrbgTestSessionHandle testSessionHandle);

/**
 ******************************************************************************
 * @ingroup LacSym
 *      Tests health of Reseed function
 * @description
 *      This function tests health of Reseed function as described
 *      in NIST SP 800-90, section 11.3.4
 *
 * @context
 *      MUST NOT be executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]   instanceHandle    Handle of instance for which DRBG is to be
 *                                tested
 * @param[in]   testSessionHandle Handle of DRBG health test session.
 *                                Physically contiguous memory for this
 *                                session should be allocated by the user.
 *
 * @return CPA_STATUS_SUCCESS    Health tests passed
 * @return CPA_STATUS_FAIL       Health tests failed
 *
 *****************************************************************************/
CpaStatus
icp_sal_drbgHTReseed(const CpaInstanceHandle instanceHandle,
                        IcpSalDrbgTestSessionHandle testSessionHandle);


#endif
