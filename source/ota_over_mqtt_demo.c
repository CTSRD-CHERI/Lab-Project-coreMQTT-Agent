/*
 * FreeRTOS V202011.00
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

/**
 * @file ota_demo_core_mqtt.c
 * @brief OTA Update example.
 *
 * The example shows how to perform an OTA update using OTA agent and the
 * coreMQTT agent.  The example creates the OTA agent task and then spins in
 * its own task publishing OTA statistics periodically within a configured
 * interval.  The OTA agent MQTT handlers are implemented using MQTT agent APIs,
 * which allows OTA application to be run concurrently with other MQTT
 * application tasks.  See https://freertos.org/mqtt/mqtt-agent-demo.html
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#include "ota_config.h"
#include "demo_config.h"

/* MQTT library includes. */
#include "freertos_mqtt_agent.h"

/* OTA Library include. */
#include "ota.h"

/* OTA Library Interface include. */
#include "ota_os_freertos.h"
#include "ota_mqtt_interface.h"
#include "ota_platform_interface.h"

/* Include firmware version struct definition. */
#include "ota_appversion32.h"

/* Include platform abstraction header. */
#include "ota_pal.h"

/*------------- Demo configurations -------------------------*/

#ifndef democonfigCLIENT_IDENTIFIER
    #error "Please define the democonfigCLIENT_IDENTIFIER with the thing name for which OTA is performed"
#endif

/**
 * @brief The maximum size of the file paths used in the demo.
 */
#define otaexampleMAX_FILE_PATH_SIZE      ( 260 )

/**
 * @brief The maximum size of the stream name required for downloading update file
 * from streaming service.
 */
#define otaexampleMAX_STREAM_NAME_SIZE    ( 128 )

/**
 * @brief The delay used in the OTA demo task to periodically output the OTA
 * statistics like number of packets received, dropped, processed and queued per connection.
 */
#define otaexampleTASK_DELAY_MS           ( 1000U )

/**
 * @brief The maximum time for which OTA demo waits for an MQTT operation to be complete.
 * This involves receiving an acknowledgment for broker for SUBSCRIBE, UNSUBSCRIBE and non
 * QOS0 publishes.
 */
#define otaexampleMQTT_TIMEOUT_MS         ( 5000U )


/**
 * @brief The common prefix for all OTA topics.
 */
#define OTA_TOPIC_PREFIX                   "$aws/things/"

/**
 * @brief The string used for jobs topics.
 */
#define OTA_TOPIC_JOBS                     "jobs"

/**
 * @brief Used to clear bits in a task's notification value.
 */
#define otaexampleMAX_UINT32               0xffffffff

/**
 * @brief The string used for streaming service topics.
 */
#define OTA_TOPIC_STREAM                   "streams"

/**
 * @brief The length of #OTA_TOPIC_PREFIX
 */
#define OTA_TOPIC_PREFIX_LENGTH            ( ( uint16_t ) ( sizeof( OTA_TOPIC_PREFIX ) - 1U ) )

/**
 * @brief Task priority of OTA agent.
 */
#define otaexampleAGENT_TASK_PRIORITY      ( tskIDLE_PRIORITY + 1 )

/**
 * @brief Maximum stack size of OTA agent task.
 */
#define otaexampleAGENT_TASK_STACK_SIZE    ( 4096 )

/**
 * @brief Application version for the firmware. OTA agent uses this
 * version number to perform anti-rollback validations.
 */
#define APP_VERSION_MAJOR                  0
#define APP_VERSION_MINOR                  9
#define APP_VERSION_BUILD                  2

/**
 * @brief Function is used by OTA agent to publish a control packet to the MQTT broker.
 *
 * The implementation of the function uses MQTT agent to queue a publish operation. It then waits
 * for the operation complete notification from agent. The notification along with result of the
 * operation is sent to the caller task using xTaksNotify APIs. The function is registerd with
 * OTA agent to invoke it whenever needed.
 *
 * @param[in] pacTopic Topic to publish the control packet to.
 * @param[in] topicLen Length of the topic string.
 * @param[in] pMsg Message to publish.
 * @param[in] msgSize Size of the message to publish.
 * @param[in] qos Qos for the publish.
 * @return OtaMqttSuccess if successful. Appropirate error code otherwise.
 */
static OtaMqttStatus_t prvMQTTPublish( const char * const pacTopic,
                                       uint16_t topicLen,
                                       const char * pMsg,
                                       uint32_t msgSize,
                                       uint8_t qos );

/**
 * @brief Function is used by OTA agent to subscribe for a control or data packet from the MQTT broker.
 *
 * The function implementation uses MQTT agent to queue the SUBSCRIBE operation and then waits for
 * a notification from agent for a subscribe completion. Notifications along with the result of the
 * operation is sent using xTaskNotify APIs. Upon acknowledgment of the subscription from the broker,
 * MQTT agent also registers the callback provided by this function with the associated topic filter.
 * The callback will be used to pass any data or control packets from the MQTT broker to
 * the OTA agent. OTA agent will invoke this function for each topic filter it needs to subscribe with the MQTT broker.
 *
 * @param[in] pTopicFilter The topic filter used to subscribe for packets.
 * @param[in] topicFilterLength Length of the topic filter string.
 * @param[in] ucQoS Intended qos value for the messages received on this topic.
 * @return OtaMqttSuccess if successful. Appropirate error code otherwise.
 */
static OtaMqttStatus_t prvMQTTSubscribe( const char * pTopicFilter,
                                         uint16_t topicFilterLength,
                                         uint8_t ucQoS );

/**
 * @brief Function is used by OTA agent to unsubscribe a topicfilter from MQTT broker.
 *
 * The function implementation queues an Unsubscribe packet with the MQTT agent. It then waits
 * for a successful completion of the operation from the agent. Notifications along with results of
 * operationre passed are sent using xTaskNotify APIs. Upon acknoweldgment of the Unsubscribe from
 * the broker MQTT agent also removes the topic filter callback registered previously, and future
 * packets if any on this topic will not be routed to the OTA agent.
 *
 * @param[in] pTopicFilter Topic filter to be unsubscibed.
 * @param[in] topicFilterLength Length of the topic filter.
 * @param[in] ucQos Qos value for the topic.
 * @return OtaMqttSuccess if successful. Appropirate error code otherwise.
 *
 */
static OtaMqttStatus_t prvMQTTUnsubscribe( const char * pTopicFilter,
                                           uint16_t topicFilterLength,
                                           uint8_t ucQoS );

/**
 * @brief Gets an unused OTA event buffer from the pool.
 *
 * OTA demo uses a simple statically allocated array of fixed size event buffers as pool. The
 * number of event buffers is configured by the param otaconfigMAX_NUM_OTA_DATA_BUFFERS
 * within ota_config.h. This function is used to fetch and queue an event buffer for processing
 * by the OTA agent task. It uses a mutex for thread safe access to the event buffer pool.
 *
 * @return A pointer to a unusued buffer. NULL if there are no buffers available.
 */
static OtaEventData_t * prvOTAEventBufferGet( void );

/**
 * @brief Free up an event buffer back to pool
 *
 * OTA demo uses a statically allocated array of fixed size event buffers as pool. The
 * number of event buffers is configured by the param otaconfigMAX_NUM_OTA_DATA_BUFFERS
 * within ota_config.h. API is used by the OTA application callback to free the OTA event buffers
 * after OTA agent has completed processing. The access to the event buffer pool is made thread safe
 * using a mutex.
 *
 * @param[in] pxBuffer Pointer to the buffer to be freed.
 */
static void prvOTAEventBufferFree( OtaEventData_t * const pxBuffer );

/**
 * @brief The function which runs the OTA agent task.
 *
 * The function calls the OTA Agent Event processing loop, which loops and process
 * any events for OTA. The loop never returns untill the OTA agent is shutdown.
 * The tasks exits gracefully in the event of an OTA agent shutdown.
 *
 * @param[in] pvParam Any parameters to be passed to OTA agent task.
 */
static void prvOTAAgentTask( void * pvParam );

/**
 * @brief The function which runs the OTA agent task.
 *
 * The function calls the OTA Agent Event processing loop, which loops and process
 * any events for OTA. The loop never returns untill the OTA agent is shutdown.
 * The tasks exits gracefully in the event of an OTA agent shutdown.
 *
 * @param[in] pvParam Any parameters to be passed to OTA agent task.
 */
static void prvOTADemoTask( void * pvParam );


/**
 * @brief The function which runs the OTA demo task.
 *
 * The function loops untill OTA agent is shutdown and reports OTA statistics
 * ( which includes blocks received, processed and dropped) at regular intervals
 *
 * @param[in] pvParam Any parameters to be passed to OTA demo task.
 */
static void prvOTADemoTask( void * pvParam );

/**
 * @brief Callback invoked for data packets received from MQTT broker.
 * Function gets invoked for any data packets received on OTA download stream topic.
 * The function is registered as a callback with MQTT agent's subscription manger with
 * associated topic filter for data stream topic. For each data packet received, the
 * function fetches a free event buffer from the pool and queues the appropirate event type for OTA agent task processing.
 *
 * @param[in] pPublishInfo Pointer to the structure containing the details of the data packet.
 * @param[in] pxSubscriptionContext Context which is passed unmodified from the MQTT agent.
 */
static void prvProcessIncomingData( MQTTPublishInfo_t * pPublishInfo,
                                    void * pxSubscriptionContext );

/**
 * @brief Callback invoked for Job related control messages from MQTT broker.
 *
 * Callback gets invoked for any job control messages from MQTT broker.
 * The function is registered as a callback with MQTT agent's subscription manger with
 * associated topic filter for job stream topic. For each job message received, the
 * function fetches a free event buffer from the pool and queues the appropirate event type for OTA agent task processing.
 *
 * @param[in] pPublishInfo Pointer to the structure containing the details of the job message.
 * @param[in] pxSubscriptionContext Context which is passed unmodified from the MQTT agent.
 */
static void prvProcessIncomingJobMessage( MQTTPublishInfo_t * pPublishInfo,
                                          void * pxSubscriptionContext );

/**
 * @brief Update File path buffer.
 */
static uint8_t updateFilePath[ otaexampleMAX_FILE_PATH_SIZE ];

/**
 * @brief Certificate File path buffer.
 */
static uint8_t certFilePath[ otaexampleMAX_FILE_PATH_SIZE ];

/**
 * @brief Stream name buffer.
 */
static uint8_t streamName[ otaexampleMAX_STREAM_NAME_SIZE ];

/**
 * @brief Decode memory.
 */
static uint8_t decodeMem[ ( 1U << otaconfigLOG2_FILE_BLOCK_SIZE ) ];

/**
 * @brief Bitmap memory.
 */
static uint8_t bitmap[ OTA_MAX_BLOCK_BITMAP_SIZE ];

/**
 * @brief OTA  Event buffer pool
 */
static OtaEventData_t eventBuffer[ otaconfigMAX_NUM_OTA_DATA_BUFFERS ] = { 0 };

/*
 * @brief Semaphore used to manage the synchronization of OTA event buffers.
 */
static SemaphoreHandle_t xBufferSemaphore;

/**
 * @brief Static handle for MQTT context.
 */
static MQTTContextHandle_t xOTAMQTTContextHandle = 0;

/**
 * @brief The buffer passed to the OTA Agent from application while initializing.
 */
static OtaAppBuffer_t otaBuffer =
{
    .pUpdateFilePath    = updateFilePath,
    .updateFilePathsize = otaexampleMAX_FILE_PATH_SIZE,
    .pCertFilePath      = certFilePath,
    .certFilePathSize   = otaexampleMAX_FILE_PATH_SIZE,
    .pStreamName        = streamName,
    .streamNameSize     = otaexampleMAX_STREAM_NAME_SIZE,
    .pDecodeMemory      = decodeMem,
    .decodeMemorySize   = ( 1U << otaconfigLOG2_FILE_BLOCK_SIZE ),
    .pFileBitmap        = bitmap,
    .fileBitmapSize     = OTA_MAX_BLOCK_BITMAP_SIZE
};


/**
 * @brief Enum for type of OTA messages received.
 */
typedef enum OtaMessageType
{
    OtaMessageTypeJob = 0,
    OtaMessageTypeStream,
    OtaNumOfMessageType
} OtaMessageType_t;

/**
 * @brief Struct for firmware version.
 */
const AppVersion32_t appFirmwareVersion =
{
    .u.x.major = APP_VERSION_MAJOR,
    .u.x.minor = APP_VERSION_MINOR,
    .u.x.build = APP_VERSION_BUILD,
};

/**
 * @brief The static callbacks for the topic filter types.
 */
static IncomingPublishCallback_t otaMessageCallback[ OtaNumOfMessageType ] = { prvProcessIncomingJobMessage, prvProcessIncomingData };
/*-----------------------------------------------------------*/

static void prvOTAEventBufferFree( OtaEventData_t * const pxBuffer )
{
    if( xSemaphoreTake( xBufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        pxBuffer->bufferUsed = false;
        ( void ) xSemaphoreGive( xBufferSemaphore );
    }
    else
    {
        LogError( ( "Failed to get buffer semaphore." ) );
    }
}

/*-----------------------------------------------------------*/

static OtaEventData_t * prvOTAEventBufferGet( void )
{
    uint32_t ulIndex = 0;
    OtaEventData_t * pFreeBuffer = NULL;

    if( xSemaphoreTake( xBufferSemaphore, portMAX_DELAY ) == pdTRUE )
    {
        for( ulIndex = 0; ulIndex < otaconfigMAX_NUM_OTA_DATA_BUFFERS; ulIndex++ )
        {
            if( eventBuffer[ ulIndex ].bufferUsed == false )
            {
                eventBuffer[ ulIndex ].bufferUsed = true;
                pFreeBuffer = &eventBuffer[ ulIndex ];
                break;
            }
        }

        ( void ) xSemaphoreGive( xBufferSemaphore );
    }
    else
    {
        LogError( ( "Failed to get buffer semaphore." ) );
    }

    return pFreeBuffer;
}

/*-----------------------------------------------------------*/
static void prvOTAAgentTask( void * pvParam )
{
    OTA_EventProcessingTask( pvParam );
    vTaskDelete( NULL );
}

/*-----------------------------------------------------------*/
static OtaMessageType_t getOtaMessageType( const char * pTopicFilter,
                                           uint16_t topicFilterLength )
{
    int retStatus = EXIT_FAILURE;

    uint16_t stringIndex = 0U, fieldLength = 0U, i = 0U;
    OtaMessageType_t retMesageType = OtaNumOfMessageType;

    /* Lookup table for OTA message string. */
    static const char * const pOtaMessageStrings[ OtaNumOfMessageType ] =
    {
        OTA_TOPIC_JOBS,
        OTA_TOPIC_STREAM
    };

    /* Check topic prefix is valid.*/
    if( strncmp( pTopicFilter, OTA_TOPIC_PREFIX, ( size_t ) OTA_TOPIC_PREFIX_LENGTH ) == 0 )
    {
        stringIndex = OTA_TOPIC_PREFIX_LENGTH;

        retStatus = EXIT_SUCCESS;
    }

    /* Check if thing name is valid.*/
    if( retStatus == EXIT_SUCCESS )
    {
        retStatus = EXIT_FAILURE;

        /* Extract the thing name.*/
        for( ; stringIndex < topicFilterLength; stringIndex++ )
        {
            if( pTopicFilter[ stringIndex ] == ( char ) '/' )
            {
                break;
            }
            else
            {
                fieldLength++;
            }
        }

        if( fieldLength > 0 )
        {
            /* Check thing name.*/
            if( strncmp( &pTopicFilter[ stringIndex - fieldLength ],
                         democonfigCLIENT_IDENTIFIER,
                         ( size_t ) ( fieldLength ) ) == 0 )
            {
                stringIndex++;

                retStatus = EXIT_SUCCESS;
            }
        }
    }

    /* Check the message type from topic.*/
    if( retStatus == EXIT_SUCCESS )
    {
        fieldLength = 0;

        /* Extract the topic type.*/
        for( ; stringIndex < topicFilterLength; stringIndex++ )
        {
            if( pTopicFilter[ stringIndex ] == ( char ) '/' )
            {
                break;
            }
            else
            {
                fieldLength++;
            }
        }

        if( fieldLength > 0 )
        {
            for( i = 0; i < OtaNumOfMessageType; i++ )
            {
                /* check thing name.*/
                if( strncmp( &pTopicFilter[ stringIndex - fieldLength ],
                             pOtaMessageStrings[ i ],
                             ( size_t ) ( fieldLength ) ) == 0 )
                {
                    break;
                }
            }

            if( i < OtaNumOfMessageType )
            {
                retMesageType = i;
            }
        }
    }

    return retMesageType;
}

/*-----------------------------------------------------------*/



/*-----------------------------------------------------------*/

/**
 * @brief The OTA agent has completed the update job or it is in
 * self test mode. If it was accepted, we want to activate the new image.
 * This typically means we should reset the device to run the new firmware.
 * If now is not a good time to reset the device, it may be activated later
 * by your user code. If the update was rejected, just return without doing
 * anything and we will wait for another job. If it reported that we should
 * start test mode, normally we would perform some kind of system checks to
 * make sure our new firmware does the basic things we think it should do
 * but we will just go ahead and set the image as accepted for demo purposes.
 * The accept function varies depending on your platform. Refer to the OTA
 * PAL implementation for your platform in aws_ota_pal.c to see what it
 * does for you.
 *
 * @param[in] event Specify if this demo is running with the AWS IoT
 * MQTT server. Set this to `false` if using another MQTT server.
 * @param[in] pData Data associated with the event.
 * @return None.
 */
static void otaAppCallback( OtaJobEvent_t event,
                            const void * pData )
{
    OtaErr_t err = OtaErrUninitialized;

    switch( event )
    {
        case OtaJobEventActivate:
            LogInfo( ( "Received OtaJobEventActivate callback from OTA Agent." ) );

            /**
             * Activate the new firmware image immediately. Applications can choose to postpone
             * the activation to a later stage if needed.
             */
            err = OTA_ActivateNewImage();

            /**
             * Activation of the new image failed. This indicates an error that requires a follow
             * up through manual activation by resetting the device. The demo reports the error
             * and shuts down the OTA agent.
             */
            LogError( ( "New image activation failed." ) );

            /* Shutdown OTA Agent without waiting. */
            OTA_Shutdown( 0 );


            break;

        case OtaJobEventFail:

            /**
             * No user action is needed here. OTA agent handles the job failure event.
             */
            LogInfo( ( "Received an OtaJobEventFail notification from OTA Agent." ) );

            break;

        case OtaJobEventStartTest:

            /* This demo just accepts the image since it was a good OTA update and networking
             * and services are all working (or we would not have made it this far). If this
             * were some custom device that wants to test other things before validating new
             * image, this would be the place to kick off those tests before calling
             * OTA_SetImageState() with the final result of either accepted or rejected. */

            LogInfo( ( "Received OtaJobEventStartTest callback from OTA Agent." ) );

            err = OTA_SetImageState( OtaImageStateAccepted );

            if( err == OtaErrNone )
            {
                LogInfo( ( "New image validation succeeded in self test mode." ) );
            }
            else
            {
                LogError( ( "Failed to set image state as accepted with error %d.", err ) );
            }

            break;

        case OtaJobEventProcessed:

            LogDebug( ( "OTA Event processing completed. Freeing the event buffer to pool." ) );
            configASSERT( pData != NULL );
            prvOTAEventBufferFree( ( OtaEventData_t * ) pData );

            break;

        case OtaJobEventSelfTestFailed:
            LogDebug( ( "Received OtaJobEventSelfTestFailed callback from OTA Agent." ) );

            /* Requires manual activation of previous image as self-test for
             * new image downloaded failed.*/
            LogError( ( "OTA Self-test failed for new image. shutting down OTA Agent." ) );

            /* Shutdown OTA Agent. */
            OTA_Shutdown( 0 );

            break;

        default:
            LogWarn( ( "Received an unhandled callback event from OTA Agent, event = %d", event ) );

            break;
    }
}

/*-----------------------------------------------------------*/

static void prvProcessIncomingData( MQTTPublishInfo_t * pPublishInfo,
                                    void * pxSubscriptionContext )
{
    configASSERT( pPublishInfo != NULL );

    ( void ) pxSubscriptionContext;

    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    LogDebug( ( "Received OTA image block, size %d.\n\n", pPublishInfo->payloadLength ) );

    configASSERT( pPublishInfo->payloadLength <= OTA_DATA_BLOCK_SIZE );

    pData = prvOTAEventBufferGet();

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedFileBlock;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "Error: No OTA data buffers available.\r\n" ) );
    }
}

/*-----------------------------------------------------------*/

static void prvProcessIncomingJobMessage( MQTTPublishInfo_t * pPublishInfo,
                                          void * pxSubscriptionContext )
{
    OtaEventData_t * pData;
    OtaEventMsg_t eventMsg = { 0 };

    ( void ) pxSubscriptionContext;

    configASSERT( pPublishInfo != NULL );

    LogInfo( ( "Received job message callback, size %d.\n\n", pPublishInfo->payloadLength ) );

    configASSERT( pPublishInfo->payloadLength <= OTA_DATA_BLOCK_SIZE );

    pData = prvOTAEventBufferGet();

    if( pData != NULL )
    {
        memcpy( pData->data, pPublishInfo->pPayload, pPublishInfo->payloadLength );
        pData->dataLength = pPublishInfo->payloadLength;
        eventMsg.eventId = OtaAgentEventReceivedJobDocument;
        eventMsg.pEventData = pData;

        /* Send job document received event. */
        OTA_SignalEvent( &eventMsg );
    }
    else
    {
        LogError( ( "Error: No OTA data buffers available.\r\n" ) );
    }
}

/*-----------------------------------------------------------*/

static void prvCommandCallback( void * pCommandContext,
                                MQTTStatus_t xReturnStatus )
{
    TaskHandle_t xTaskToNotify = ( TaskHandle_t ) pCommandContext;

    configASSERT( xTaskToNotify );
    xTaskNotify( xTaskToNotify, xReturnStatus, eSetValueWithOverwrite );
}

/*-----------------------------------------------------------*/
static MQTTStatus_t prvSubscribeToTopic( MQTTQoS_t xQoS,
                                         char * pcTopicFilter,
                                         IncomingPublishCallback_t pCallback )
{
    MQTTStatus_t mqttStatus;
    uint32_t ulNotifiedValue;
    MQTTSubscribeInfo_t xSubscribeInfo[ 1 ] = { 0 };
    BaseType_t result;

    TaskHandle_t xTaskHandle = xTaskGetCurrentTaskHandle();

    xSubscribeInfo[ 0 ].pTopicFilter = pcTopicFilter;
    xSubscribeInfo[ 0 ].topicFilterLength = ( uint16_t ) strlen( pcTopicFilter );
    xSubscribeInfo[ 0 ].qos = xQoS;

    LogInfo( ( " Subscribing to topic filter: %s", pcTopicFilter ) );
    xTaskNotifyStateClear( NULL );

    mqttStatus = MQTTAgent_Subscribe( xOTAMQTTContextHandle,
                                      xSubscribeInfo,
                                      pCallback,
                                      NULL,
                                      prvCommandCallback,
                                      ( void * ) xTaskHandle,
                                      otaexampleMQTT_TIMEOUT_MS );

    /* Wait for command to complete so MQTTSubscribeInfo_t remains in scope for the
     * duration of the command. */
    if( mqttStatus == MQTTSuccess )
    {
        result = xTaskNotifyWait( 0, otaexampleMAX_UINT32, &ulNotifiedValue, pdMS_TO_TICKS( otaexampleMQTT_TIMEOUT_MS ) );

        if( result == pdTRUE )
        {
            mqttStatus = ( MQTTStatus_t ) ulNotifiedValue;
        }
        else
        {
            mqttStatus = MQTTRecvFailed;
        }
    }

    return mqttStatus;
}

static OtaMqttStatus_t prvMQTTSubscribe( const char * pTopicFilter,
                                         uint16_t topicFilterLength,
                                         uint8_t ucQoS )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    OtaMessageType_t otaMessageType;
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    configASSERT( pTopicFilter != NULL );
    configASSERT( topicFilterLength > 0 );

    otaMessageType = getOtaMessageType( pTopicFilter, topicFilterLength );
    configASSERT( otaMessageType < OtaNumOfMessageType );

    /* Send SUBSCRIBE packet. */
    mqttStatus = prvSubscribeToTopic( ucQoS,
                                      pTopicFilter,
                                      otaMessageCallback[ otaMessageType ] );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to SUBSCRIBE to topic with error = %u.",
                    mqttStatus ) );

        otaRet = OtaMqttSubscribeFailed;
    }
    else
    {
        LogInfo( ( "SUBSCRIBE topic %.*s to broker.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );

        otaRet = OtaMqttSuccess;
    }

    return otaRet;
}

static OtaMqttStatus_t prvMQTTPublish( const char * const pacTopic,
                                       uint16_t topicLen,
                                       const char * pMsg,
                                       uint32_t msgSize,
                                       uint8_t qos )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    BaseType_t result;
    MQTTStatus_t mqttStatus = MQTTBadParameter;
    MQTTPublishInfo_t publishInfo = { 0 };
    TaskHandle_t xTaskHandle;
    uint32_t ulNotifiedValue;

    publishInfo.pTopicName = pacTopic;
    publishInfo.topicNameLength = topicLen;
    publishInfo.qos = qos;
    publishInfo.pPayload = pMsg;
    publishInfo.payloadLength = msgSize;

    xTaskHandle = xTaskGetCurrentTaskHandle();
    xTaskNotifyStateClear( NULL );

    mqttStatus = MQTTAgent_Publish( xOTAMQTTContextHandle,
                                    &publishInfo,
                                    prvCommandCallback,
                                    ( void * ) xTaskHandle,
                                    otaexampleMQTT_TIMEOUT_MS );

    /* Wait for command to complete so MQTTSubscribeInfo_t remains in scope for the
     * duration of the command. */
    if( mqttStatus == MQTTSuccess )
    {
        result = xTaskNotifyWait( 0, otaexampleMAX_UINT32, &ulNotifiedValue, pdMS_TO_TICKS( otaexampleMQTT_TIMEOUT_MS ) );

        if( result != pdTRUE )
        {
            mqttStatus = MQTTSendFailed;
        }
        else
        {
            mqttStatus = ( MQTTStatus_t ) ( ulNotifiedValue );
        }
    }

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send PUBLISH packet to broker with error = %u.", mqttStatus ) );
        otaRet = OtaMqttPublishFailed;
    }
    else
    {
        LogInfo( ( "Sent PUBLISH packet to broker %.*s to broker.\n\n",
                   topicLen,
                   pacTopic ) );

        otaRet = OtaMqttSuccess;
    }

    return otaRet;
}

static MQTTStatus_t prvUnSubscribeFromTopic( MQTTQoS_t xQoS,
                                             char * pcTopicFilter )
{
    MQTTStatus_t mqttStatus;
    uint32_t ulNotifiedValue;
    MQTTSubscribeInfo_t xSubscribeInfo[ 1 ] = { 0 };
    int index = 0;
    BaseType_t result;

    TaskHandle_t xTaskHandle = xTaskGetCurrentTaskHandle();

    xSubscribeInfo[ index ].pTopicFilter = pcTopicFilter;
    xSubscribeInfo[ index ].topicFilterLength = ( uint16_t ) strlen( pcTopicFilter );
    xSubscribeInfo[ index ].qos = xQoS;

    LogInfo( ( " Unsubscribing to topic filter: %s", pcTopicFilter ) );
    xTaskNotifyStateClear( NULL );


    mqttStatus = MQTTAgent_Unsubscribe( xOTAMQTTContextHandle,
                                        xSubscribeInfo,
                                        prvCommandCallback,
                                        ( void * ) xTaskHandle,
                                        otaexampleMQTT_TIMEOUT_MS );

    /* Wait for command to complete so MQTTSubscribeInfo_t remains in scope for the
     * duration of the command. */
    if( mqttStatus == MQTTSuccess )
    {
        result = xTaskNotifyWait( 0, otaexampleMAX_UINT32, &ulNotifiedValue, pdMS_TO_TICKS( otaexampleMQTT_TIMEOUT_MS ) );

        if( result == pdTRUE )
        {
            mqttStatus = ( MQTTStatus_t ) ( ulNotifiedValue );
        }
        else
        {
            mqttStatus = MQTTRecvFailed;
        }
    }

    return mqttStatus;
}

static OtaMqttStatus_t prvMQTTUnsubscribe( const char * pTopicFilter,
                                           uint16_t topicFilterLength,
                                           uint8_t ucQoS )
{
    OtaMqttStatus_t otaRet = OtaMqttSuccess;
    MQTTStatus_t mqttStatus = MQTTBadParameter;

    configASSERT( pTopicFilter != NULL );
    configASSERT( topicFilterLength > 0 );

    /* Send SUBSCRIBE packet. */
    mqttStatus = prvUnSubscribeFromTopic( ucQoS,
                                          pTopicFilter );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to UNSUBSCRIBE from topic %.*s with error = %u.",
                    topicFilterLength,
                    pTopicFilter,
                    mqttStatus ) );

        otaRet = OtaMqttUnsubscribeFailed;
    }
    else
    {
        LogInfo( ( "UNSUBSCRIBED from topic %.*s.\n\n",
                   topicFilterLength,
                   pTopicFilter ) );

        otaRet = OtaMqttSuccess;
    }

    return otaRet;
}

/*-----------------------------------------------------------*/

static void setOtaInterfaces( OtaInterfaces_t * pOtaInterfaces )
{
    configASSERT( pOtaInterfaces != NULL );

    /* Initialize OTA library OS Interface. */
    pOtaInterfaces->os.event.init = OtaInitEvent_FreeRTOS;
    pOtaInterfaces->os.event.send = OtaSendEvent_FreeRTOS;
    pOtaInterfaces->os.event.recv = OtaReceiveEvent_FreeRTOS;
    pOtaInterfaces->os.event.deinit = OtaDeinitEvent_FreeRTOS;
    pOtaInterfaces->os.timer.start = OtaStartTimer_FreeRTOS;
    pOtaInterfaces->os.timer.stop = OtaStopTimer_FreeRTOS;
    pOtaInterfaces->os.timer.delete = OtaDeleteTimer_FreeRTOS;
    pOtaInterfaces->os.mem.malloc = Malloc_FreeRTOS;
    pOtaInterfaces->os.mem.free = Free_FreeRTOS;

    /* Initialize the OTA library MQTT Interface.*/
    pOtaInterfaces->mqtt.subscribe = prvMQTTSubscribe;
    pOtaInterfaces->mqtt.publish = prvMQTTPublish;
    pOtaInterfaces->mqtt.unsubscribe = prvMQTTUnsubscribe;

    /* Initialize the OTA library PAL Interface.*/
    pOtaInterfaces->pal.getPlatformImageState = otaPal_GetPlatformImageState;
    pOtaInterfaces->pal.setPlatformImageState = otaPal_SetPlatformImageState;
    pOtaInterfaces->pal.writeBlock = otaPal_WriteBlock;
    pOtaInterfaces->pal.activate = otaPal_ActivateNewImage;
    pOtaInterfaces->pal.closeFile = otaPal_CloseFile;
    pOtaInterfaces->pal.reset = otaPal_ResetDevice;
    pOtaInterfaces->pal.abort = otaPal_Abort;
    pOtaInterfaces->pal.createFile = otaPal_CreateFileForRx;
}

static void prvOTADemoTask( void * pvParam )
{
    ( void ) pvParam;
    /* FreeRTOS APIs return status. */
    BaseType_t xResult = pdPASS;

    /* OTA library return status. */
    OtaErr_t otaRet = OtaErrNone;

    /* OTA event message used for sending event to OTA Agent.*/
    OtaEventMsg_t eventMsg = { 0 };

    /* OTA interface context required for library interface functions.*/
    OtaInterfaces_t otaInterfaces;

    /* OTA library packet statistics per job.*/
    OtaAgentStatistics_t otaStatistics = { 0 };

    /* OTA Agent state returned from calling OTA_GetAgentState.*/
    OtaState_t state = OtaAgentStateStopped;

    /* Set OTA Library interfaces.*/
    setOtaInterfaces( &otaInterfaces );

    LogInfo( ( "OTA over MQTT demo, Application version %u.%u.%u",
               appFirmwareVersion.u.x.major,
               appFirmwareVersion.u.x.minor,
               appFirmwareVersion.u.x.build ) );
    /****************************** Init OTA Library. ******************************/

    xBufferSemaphore = xSemaphoreCreateMutex();

    if( xBufferSemaphore == NULL )
    {
        xResult = pdFAIL;
    }

    if( xResult == pdPASS )
    {
        memset( eventBuffer, 0x00, sizeof( eventBuffer ) );

        if( ( otaRet = OTA_Init( &otaBuffer,
                                 &otaInterfaces,
                                 ( const uint8_t * ) ( democonfigCLIENT_IDENTIFIER ),
                                 otaAppCallback ) ) != OtaErrNone )
        {
            LogError( ( "Failed to initialize OTA Agent, exiting = %u.",
                        otaRet ) );
            xResult = pdFAIL;
        }
    }

    if( xResult == pdPASS )
    {
        if( ( xResult = xTaskCreate( prvOTAAgentTask,
                                     "OTAAgentTask",
                                     otaexampleAGENT_TASK_STACK_SIZE,
                                     NULL,
                                     otaexampleAGENT_TASK_PRIORITY,
                                     NULL ) ) != pdPASS )
        {
            LogError( ( "Failed to start OTA Agent task: "
                        ",errno=%d",
                        xResult ) );
        }
    }

    /***************************Start OTA demo loop. ******************************/

    if( xResult == pdPASS )
    {
        /* Start the OTA Agent.*/
        eventMsg.eventId = OtaAgentEventStart;
        OTA_SignalEvent( &eventMsg );

        while( ( ( state = OTA_GetState() ) != OtaAgentStateStopped ) )
        {
            /* Get OTA statistics for currently executing job. */
            OTA_GetStatistics( &otaStatistics );
            LogInfo( ( " Received: %u   Queued: %u   Processed: %u   Dropped: %u",
                       otaStatistics.otaPacketsReceived,
                       otaStatistics.otaPacketsQueued,
                       otaStatistics.otaPacketsProcessed,
                       otaStatistics.otaPacketsDropped ) );

            vTaskDelay( pdMS_TO_TICKS( otaexampleTASK_DELAY_MS ) );
        }
    }

    LogInfo( ( "OTA agent task stopped. Exiting OTA demo." ) );

    vTaskDelete( NULL );
}

void vStartOTACodeSigningDemo( configSTACK_DEPTH_TYPE uxStackSize,
                               UBaseType_t uxPriority )
{
    BaseType_t xResult;

    if( ( xResult = xTaskCreate( prvOTADemoTask,
                                 "OTADemoTask",
                                 uxStackSize,
                                 NULL,
                                 uxPriority,
                                 NULL ) ) != pdPASS )
    {
        LogError( ( "Failed to start OTA task: "
                    ",errno=%d",
                    xResult ) );
    }

    configASSERT( xResult == pdPASS );
}
void vSuspendOTACodeSigningDemo( void )
{
    if( ( OTA_GetState() != OtaAgentStateSuspended ) && ( OTA_GetState() != OtaAgentStateStopped ) )
    {
        OTA_Suspend();

        while( ( OTA_GetState() != OtaAgentStateSuspended ) &&
               ( OTA_GetState() != OtaAgentStateStopped ) )
        {
            vTaskDelay( pdMS_TO_TICKS( otaexampleTASK_DELAY_MS ) );
        }
    }
}

void vResumeOTACodeSigningDemo( void )
{
    if( OTA_GetState() == OtaAgentStateSuspended )
    {
        OTA_Resume();

        while( OTA_GetState() == OtaAgentStateSuspended )
        {
            vTaskDelay( pdMS_TO_TICKS( otaexampleTASK_DELAY_MS ) );
        }
    }
}