/*
 * FreeRTOS OTA PAL for platforms having FreeRTOS-FAT
 *
 * Copyright (c) 2021 Hesham Almatary <Hesham.Almatary@cl.cam.ac.uk>
 * See LICENSE_CHERI
 *
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* OTA PAL implementation for platforms having FreeRTOS-FAT */

#include <stdio.h>
#include <stdlib.h>
#include "FreeRTOS.h"
#include "ota_config.h"

#include "iot_crypto.h"
#include "ota.h"

#include "aws_ota_codesigner_certificate.h"
#include "ota_pal.h"

/* FreeRTOS+FAT headers. */
#include "ff_headers.h"
#include "ff_stdio.h"

/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha256-ecdsa";

static OtaPalMainStatus_t otaPal_CheckFileSignature( OtaFileContext_t * const C );
static uint8_t * otaPal_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize );

/*-----------------------------------------------------------*/

static inline BaseType_t prvContextValidate( OtaFileContext_t* pFileContext )
{
    return( ( pFileContext != NULL ) &&
            ( pFileContext->pFile != NULL ) ); /*lint !e9034 Comparison is correct for file pointer type. */
}

/* Used to set the high bit of Windows error codes for a negative return value. */
#define OTA_PAL_INT16_NEGATIVE_MASK    ( 1 << 15 )

/* Size of buffer used in file operations on this platform. */
#define OTA_PAL_BUF_SIZE ( ( size_t ) 4096UL )

/* Attempt to create a new receive file for the file chunks as they come in. */

OtaPalStatus_t otaPal_CreateFileForRx( OtaFileContext_t* const C )
{
    OtaPalMainStatus_t mainErr = OtaPalUninitialized;
    OtaPalSubStatus_t subErr = 0;

    if( C != NULL )
    {
        if ( C->pFilePath != NULL )
        {
            C->pFile = ff_fopen(  ( const char * )C->pFilePath, "w" );

            if ( C->pFile != NULL )
            {
                mainErr = OtaPalSuccess;
                /* Write zeros of the requested file size to create an FF_FILE
                 * of that file as ff_fseek doesn't increase the file size and fails
                 * when trying to seek a position larger than the default assigned
                 * file size
                 */
                BaseType_t zeros = 0;
                ff_fwrite( &zeros, sizeof(uint64_t), ( C->fileSize / sizeof( BaseType_t )), ( FF_FILE * ) C->pFile );

                LogInfo( ( "Receive file created.\r\n" ) );
            }
            else
            {
                mainErr = OtaPalRxFileCreateFailed;
                LogError( ( "ERROR - Failed to start operation: already active!\r\n" ) );
            }
        }
        else
        {
            mainErr = OtaPalRxFileCreateFailed;
            LogError( ( "ERROR - Invalid filepath in filecontext.\r\n" ) );
        }
    }
    else
    {
        mainErr = OtaPalRxFileCreateFailed;
        LogError( ( "ERROR - Invalid file context provided.\r\n" ) );
    }

    return OTA_PAL_COMBINE_ERR(mainErr,subErr);
}


/* Abort receiving the specified OTA update by closing the file. */

OtaPalStatus_t otaPal_Abort( OtaFileContext_t * const C )
{
    /* Set default return status to uninitialized. */
    OtaPalMainStatus_t mainErr = OtaPalUninitialized;
    OtaPalSubStatus_t subErr = 0;
    int32_t lFileCloseResult;

    if( NULL != C )
    {
        /* Close the OTA update file if it's open. */
        if( NULL != C->pFile )
        {
            lFileCloseResult = ff_fclose( ( FF_FILE * ) C->pFile );

            C->pFile = NULL;

            if( 0 == lFileCloseResult )
            {
                LogInfo( ( "File closed.\r\n" ) );
                mainErr = OtaPalSuccess;
            }
            else /* Failed to close file. */
            {
                LogError( ( "ERROR - Closing file failed.\r\n" ) );
                mainErr = OtaPalFileAbort;
            }
        }
        else
        {
            /* Nothing to do. No open file associated with this context. */
            mainErr = OtaPalSuccess;
        }
    }
    else /* Context was not valid. */
    {
        LogError( ( "ERROR - Invalid context.\r\n" ) );
        mainErr = OtaPalFileAbort;
    }

    return OTA_PAL_COMBINE_ERR(mainErr,subErr);
}

/* Write a block of data to the specified file. */
int16_t otaPal_WriteBlock( OtaFileContext_t * const C,
                           uint32_t ulOffset,
                           uint8_t * const pacData,
                           uint32_t ulBlockSize )
{
    int32_t lResult = 0;

    if( prvContextValidate( C ) == pdTRUE )
    {
        lResult = ff_fseek ( ( FF_FILE * ) C->pFile, ulOffset, FF_SEEK_SET );

        if( 0 == lResult )
        {
            lResult = ff_fwrite( pacData, ulBlockSize, 1, ( FF_FILE * ) C->pFile );

            if( lResult < 0 )
            {
                LogError( ( "ERROR - fwrite failed\r\n" ) );
                /* Mask to return a negative value. */
                lResult = OTA_PAL_INT16_NEGATIVE_MASK; /*lint !e40 !e9027
                                                                * Errno is being used in accordance with host API documentation.
                                                                * Bitmasking is being used to preserve host API error with library status code. */
            }
        }
        else
        {
            LogError( ( "ERROR - fseek failed\r\n" ) );
            /* Mask to return a negative value. */
            lResult = OTA_PAL_INT16_NEGATIVE_MASK; /*lint !e40 !e9027
                                                            * Errno is being used in accordance with host API documentation.
                                                            * Bitmasking is being used to preserve host API error with library status code. */
        }
    }
    else /* Invalid context or file pointer provided. */
    {
        LogError( ( "ERROR - Invalid context.\r\n" ) );
        lResult = -1; /*TODO: Need a negative error code from the PAL here. */
    }

    return ( int16_t ) lResult;
}

/* Close the specified file. This shall authenticate the file if it is marked as secure. */

OtaPalStatus_t otaPal_CloseFile( OtaFileContext_t * const C )
{
    OtaPalMainStatus_t mainErr = OtaPalUninitialized;
    OtaPalSubStatus_t subErr = 0;
    int32_t lError = 0;

    if( prvContextValidate( C ) == pdTRUE )
    {
        if( C->pSignature != NULL )
        {
            /* Verify the file signature, close the file and return the signature verification result. */
            mainErr = otaPal_CheckFileSignature( C );
        }
        else
        {
            LogError( ( "NULL OTA Signature structure.\r\n" ) );
            mainErr = OtaPalSignatureCheckFailed;
        }

        /* Close the file. */
        lError = ff_fclose( ( FF_FILE * ) C->pFile );

        C->pFile = NULL;

        if( lError != 0 )
        {
			LogError( ( "Failed to close OTA update file.\r\n" ) );
            mainErr = OtaPalFileClose;
        }

        if( mainErr == OtaPalSuccess )
        {
            LogInfo( ( "%s signature verification passed.\r\n", OTA_JsonFileSignatureKey ) );
        }
        else
        {
            LogError( ( "Failed to pass %s signature verification: %d.\r\n",
                        OTA_JsonFileSignatureKey, OTA_PAL_COMBINE_ERR(mainErr,subErr) ) );

			/* If we fail to verify the file signature that means the image is not valid. We need to set the image state to aborted. */
			otaPal_SetPlatformImageState( C, OtaImageStateAborted );

        }
    }
    else /* Invalid OTA Context. */
    {
        /* FIXME: Invalid error code for a null file context and file handle. */
		LogError( ( "Invalid file context.\r\n" ) );
        mainErr = OtaPalFileClose;
    }

    return OTA_PAL_COMBINE_ERR(mainErr,subErr);
}


/* Verify the signature of the specified file. */

static OtaPalMainStatus_t otaPal_CheckFileSignature( OtaFileContext_t * const C )
{
    OtaPalMainStatus_t eResult = OtaPalSuccess;
    uint32_t ulBytesRead;
    uint32_t ulSignerCertSize;
    uint8_t * pucBuf, * pucSignerCert;
    void * pvSigVerifyContext;

    if( prvContextValidate( C ) == pdTRUE )
    {
        /* Verify an ECDSA-SHA256 signature. */
        if( pdFALSE == CRYPTO_SignatureVerificationStart( &pvSigVerifyContext, cryptoASYMMETRIC_ALGORITHM_ECDSA, cryptoHASH_ALGORITHM_SHA256 ) )
        {
            eResult = OtaPalSignatureCheckFailed;
        }
        else
        {
            LogInfo( ( "Started %s signature verification, file: %s\r\n",
                        OTA_JsonFileSignatureKey, ( const char * ) C->pCertFilepath ) );
            pucSignerCert = otaPal_ReadAndAssumeCertificate( ( const uint8_t * const ) C->pCertFilepath, &ulSignerCertSize );

            if( pucSignerCert != NULL )
            {
                pucBuf = pvPortMalloc( OTA_PAL_BUF_SIZE ); /*lint !e9079 Allow conversion. */

                if( pucBuf != NULL )
                {
                    /* Rewind the received file to the beginning. */
                    if ( ff_fseek ( ( FF_FILE * ) C->pFile, 0L, FF_SEEK_SET) )
                    {
                        do
                        {
                            ulBytesRead = ff_fread( pucBuf, OTA_PAL_BUF_SIZE, 1, ( FF_FILE * ) C->pFile );
                            /* Include the file chunk in the signature validation. Zero size is OK. */
                            CRYPTO_SignatureVerificationUpdate( pvSigVerifyContext, pucBuf, ulBytesRead );
                        } while( ulBytesRead > 0UL );

                        if( pdFALSE == CRYPTO_SignatureVerificationFinal( pvSigVerifyContext,
                                                                          ( char * ) pucSignerCert,
                                                                          ( size_t ) ulSignerCertSize,
                                                                          C->pSignature->data,
                                                                          C->pSignature->size ) ) /*lint !e732 !e9034 Allow comparison in this context. */
                        {
                            eResult = OtaPalSignatureCheckFailed;
                        }
						pvSigVerifyContext = NULL;	/* The context has been freed by CRYPTO_SignatureVerificationFinal(). */
                    }
                    else
                    {
                        /* Nothing special to do. */
                    }

                    /* Free the temporary file page buffer. */
                    vPortFree( pucBuf );
                }
                else
                {
                    LogError( ( "Failed to allocate buffer memory.\r\n" ) );
                    eResult = OtaPalOutOfMemory;
                }

                /* Free the signer certificate that we now own after prvReadAndAssumeCertificate(). */
                vPortFree( pucSignerCert );
            }
            else
            {
                eResult = OtaPalBadSignerCert;
            }
        }
    }
    else
    {
        /* FIXME: Invalid error code for a NULL file context. */
        LogError( ( "Invalid OTA file context.\r\n" ) );
        /* Invalid OTA context or file pointer. */
        eResult = OtaPalNullFileContext;
    }

    return eResult;
}


/* Read the specified signer certificate from the filesystem into a local buffer. The allocated
 * memory becomes the property of the caller who is responsible for freeing it.
 */

static uint8_t * otaPal_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize )
{
    FF_FILE * pFile;
    uint8_t * pucSignerCert = NULL;
    uint8_t * pucCertData = NULL;
    int32_t lSize = 0; /* For MISRA mandatory. */
    int32_t lError;

    pFile = ff_fopen( ( const char * ) pucCertName, "r" );

    if( pFile != NULL )
    {
        lError = ff_fseek ( pFile, 0L, FF_SEEK_SET );

        if( lError == 0 )                               /* fseek returns a non-zero value on error. */
        {
            lSize = (int32_t) ff_ftell( pFile );

            if( lSize != -1L )                                 /* ftell returns -1 on error. */
            {
                lError = ff_fseek ( pFile, 0L, FF_SEEK_SET );
            }
            else /* ftell returned an error, pucSignerCert remains NULL. */
            {
                lError = -1L;
            }
        } /* else fseek returned an error, pucSignerCert remains NULL. */

        if( lError == 0 )
        {
            /* Allocate memory for the signer certificate plus a terminating zero so we can load and return it to the caller. */
            pucSignerCert = pvPortMalloc( lSize + 1 ); /*lint !e732 !e9034 !e9079 Allow conversion. */
        }

        if( pucSignerCert != NULL )
        {
            if( ff_fread( pucSignerCert, lSize, 1, pFile ) == ( size_t ) lSize )
            {
                /* The crypto code requires the terminating zero to be part of the length so add 1 to the size. */
                *ulSignerCertSize = lSize + 1;
                pucSignerCert[ lSize ] = 0;
            }
            else
            {   /* There was a problem reading the certificate file so free the memory and abort. */
                vPortFree( pucSignerCert );
                pucSignerCert = NULL;
            }
        }
        else
        {
            LogError( ( "Failed to allocate memory for signer cert contents.\r\n" ) );
            /* Nothing special to do. */
        }

        lError = ff_fclose( pFile );

        if( lError != 0 )
        {
			LogError( ( "File pointer operation failed.\r\n" ) );
            pucSignerCert = NULL;
        }
    }
    else
    {
		LogError( ( "No such certificate file: %s. Using aws_ota_codesigner_certificate.h.\r\n",
                    ( const char * ) pucCertName ) );

        /* Allocate memory for the signer certificate plus a terminating zero so we can copy it and return to the caller. */
        lSize = sizeof( signingcredentialSIGNING_CERTIFICATE_PEM );
        pucSignerCert = pvPortMalloc( lSize );                           /*lint !e9029 !e9079 !e838 malloc proto requires void*. */
        pucCertData = ( uint8_t * ) signingcredentialSIGNING_CERTIFICATE_PEM; /*lint !e9005 we don't modify the cert but it could be set by PKCS11 so it's not const. */

        if( pucSignerCert != NULL )
        {
            memcpy( pucSignerCert, pucCertData, lSize );
            *ulSignerCertSize = lSize;
        }
        else
        {
			LogError( ( "No memory for certificate of size %d!\r\n", lSize ) );
        }
    }

    return pucSignerCert; /*lint !e480 !e481 fopen and fclose are being used by-design. */
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_ResetDevice( OtaFileContext_t* const pFileContext )
{
	(void)pFileContext;

    /* Return no error.  Windows implementation does not reset device. */
    return OTA_PAL_COMBINE_ERR(OtaPalSuccess,0);
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_ActivateNewImage( OtaFileContext_t* const pFileContext )
{
	(void)pFileContext;

    /* Return no error. Windows implementation simply does nothing on activate.
     * To run the new firmware image, double click the newly downloaded exe */
    return OTA_PAL_COMBINE_ERR(OtaPalSuccess,0);
}


/*
 * Set the final state of the last transferred (final) OTA file (or bundle).
 * On Windows, the state of the OTA image is stored in PlaformImageState.txt.
 */

OtaPalStatus_t otaPal_SetPlatformImageState( OtaFileContext_t * const pFileContext, OtaImageState_t eState )
{
	(void)pFileContext;

    OtaPalMainStatus_t mainErr = OtaPalSuccess;
    OtaPalSubStatus_t subErr = 0;
    FF_FILE * pstPlatformImageState;

    if( eState != OtaImageStateUnknown && eState <= OtaLastImageState )
    {
        pstPlatformImageState = ff_fopen( "PlatformImageState.txt", "w" );

        if( pstPlatformImageState != NULL )
        {
            /* Write the image state to PlatformImageState.txt. */
            if( 1 != ff_fwrite( &eState, sizeof( OtaImageState_t ), 1, pstPlatformImageState) )
            {
				LogError( ( "Unable to write to image state file.\r\n" ) );
                mainErr = OtaPalBadImageState;
            }

            /* Close PlatformImageState.txt. */
            if( 0 != ff_fclose( pstPlatformImageState ) )
            {
				LogError( ( "Unable to close image state file.\r\n" ) );
                mainErr = OtaPalBadImageState;
            }
        }
        else
        {
			LogError( ( "Unable to open image state file.\r\n" ) );
            mainErr = OtaPalBadImageState;
        }
    } /*lint !e481 Allow fopen and fclose calls in this context. */
    else /* Image state invalid. */
    {
		LogError( ( "ERROR - Invalid image state provided.\r\n" ) );
        mainErr = OtaPalBadImageState;
    }

    return OTA_PAL_COMBINE_ERR(mainErr,subErr); 
}

/* Get the state of the currently running image.
 *
 * On Windows, this is simulated by looking for and reading the state from
 * the PlatformImageState.txt file in the current working directory.
 *
 * We read this at OTA_Init time so we can tell if the MCU image is in self
 * test mode. If it is, we expect a successful connection to the OTA services
 * within a reasonable amount of time. If we don't satisfy that requirement,
 * we assume there is something wrong with the firmware and reset the device,
 * causing it to rollback to the previous code. On Windows, this is not
 * fully simulated as there is no easy way to reset the simulated device.
 */
OtaPalImageState_t otaPal_GetPlatformImageState( OtaFileContext_t * const pFileContext )
{
	(void)pFileContext;

    FF_FILE * pstPlatformImageState;
	OtaImageState_t eSavedAgentState = OtaImageStateUnknown;
	OtaPalImageState_t ePalState = OtaPalImageStateUnknown;

    pstPlatformImageState = ff_fopen( "PlatformImageState.txt", "r" );

    if( pstPlatformImageState != NULL )
    {
        if( 1 != ff_fread( &eSavedAgentState, sizeof(OtaImageState_t), 1, pstPlatformImageState ) )
        {
            /* If an error occured reading the file, mark the state as aborted. */
            LogError( ( "Unable to read image state file.\r\n" ) );
			ePalState = OtaPalImageStateInvalid;
        }
		else
		{
			switch (eSavedAgentState)
			{
				case OtaImageStateTesting:
					ePalState = OtaPalImageStatePendingCommit;
					break;
				case OtaImageStateAccepted:
					ePalState = OtaPalImageStateValid;
					break;
				case OtaImageStateRejected:
				case OtaImageStateAborted:
				default:
					ePalState = OtaPalImageStateInvalid;
					break;
			}
		}


        if( 0 != ff_fclose( pstPlatformImageState ) )
        {
            LogError( ( "Unable to close image state file.\r\n" ) );
			ePalState = OtaPalImageStateInvalid;
        }
    }
    else
    {
        /* If no image state file exists, assume a factory image. */
		ePalState = OtaPalImageStateValid; /*lint !e64 Allow assignment. */
    }

    return ePalState; /*lint !e64 !e480 !e481 I/O calls and return type are used per design. */
}

/*-----------------------------------------------------------*/

/* Provide access to private members for testing. */
#ifdef FREERTOS_ENABLE_UNIT_TESTS
#include "aws_ota_pal_test_access_define.h"
#endif
