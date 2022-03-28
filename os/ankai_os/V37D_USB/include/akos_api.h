#ifndef __AKOS_API_H__
#define __AKOS_API_H__

#include "anyka_types.h"
#include "akos_error.h"


#define LIB_VER     "AKOS V2.0.08"

//charlie add begin
#define OS_FAIL     -1
#define OS_SUCCESS  0


//charlie add end
typedef long				T_hTask;
typedef long				T_hQueue;
typedef long				T_hSemaphore;
typedef long				T_hHisr;
typedef unsigned char				T_OPTION;
typedef long				T_hMailbox;
typedef long				T_hEventGroup;
typedef long				T_hTimer;

/* Define constants for use in service parameters.  */

#define         AK_AND                          2
#define         AK_AND_CONSUME                  3
#define         AK_DISABLE_TIMER                4
#define         AK_ENABLE_TIMER                 5
#define         AK_FIFO                         6
#define         AK_FIXED_SIZE                   7
#define         AK_NO_PREEMPT                   8
#define         AK_NO_START                     9
#define         AK_NO_SUSPEND                   0
#define         AK_OR                           0
#define         AK_OR_CONSUME                   1
#define         AK_PREEMPT                      10
#define         AK_PRIORITY                     11
#define         AK_START                        12
#define         AK_SUSPEND                      0xFFFFFFFFUL
#define         AK_VARIABLE_SIZE                13

/* Define task suspension constants.  */

#define         AK_DRIVER_SUSPEND               10
#define         AK_EVENT_SUSPEND                7
#define         AK_FINISHED                     11
#define         AK_MAILBOX_SUSPEND              3
#define         AK_MEMORY_SUSPEND               9
#define         AK_PARTITION_SUSPEND            8
#define         AK_PIPE_SUSPEND                 5
#define         AK_PURE_SUSPEND                 1
#define         AK_QUEUE_SUSPEND                4
#define         AK_READY                        0
#define         AK_SEMAPHORE_SUSPEND            6
#define         AK_SLEEP_SUSPEND                2
#define         AK_TERMINATED                   12

/* Define task status. */

#define         AK_DRIVER_SUSPEND               10
#define         AK_EVENT_SUSPEND                7
#define         AK_FINISHED                     11
#define         AK_MAILBOX_SUSPEND              3
#define         AK_MEMORY_SUSPEND               9
#define         AK_PARTITION_SUSPEND            8
#define         AK_PIPE_SUSPEND                 5
#define         AK_PURE_SUSPEND                 1
#define         AK_QUEUE_SUSPEND                4
#define         AK_READY                        0
#define         AK_SEMAPHORE_SUSPEND            6
#define         AK_SLEEP_SUSPEND                2
#define         AK_TERMINATED                   12

typedef bool (*CallbakCompare)(const void *evtParm1, const void *evtParm2);

// Task Control API


/*@brief: 此项服务创建一个应用程序任务
  *
  *@param task entry 		[in]指定任务函数入口
  *@param name 				[in]任务名字符串指针，最长只有8字节
  *@param argc				[in]unsigned long数据类型，可以用来传递初始化信息到任务
  *@param argv				[in]指针，传递初始化信息到任务
  *@param stack_address		[in]分配任务堆栈区的起始内存地址位置
  *@param stack_size      	[in]指定堆栈的字节数
  *@param priority          [in]在0～255之间指定优先级值。数值越低，任务级别越高。
  *@param time_slice		[in]表示中止运行任务的定时器节拍最大值。0值表示禁止任务时间片。
  *@param preempt       	[in]此配置的有效参数为AK_PREEMPT和AK_NO_PREEMPT。  AK_PREEMPT表示任务占先有效，AK_NO_PREEMPT表示任务占先无效。  注：如果任务占先无效，时间片禁止
  *@param auto_start     	[in]  此配置有效参数为：AK_NO_START和AK_START。AK_START表示在任务创建后把任务放置到就绪状态。AK_NO_START  表示任务在创建之后处于休眠状态。  参数为AK_NO_START的任务稍后必须恢复。
  *
  *@return T_hTask: Tash handle
  *@如果出错，返回错误值，小于0
  *@AK_MEMORY_CORRUPT	表示申请内存空间失败
  *@AK_INVALID_ENTRY	表示入口函数指针为空
  *@AK_INVALID_MEMORY  	表示stack_address指定的内存区为空
  *@AK_INVALID_SIZE 		表示指定的堆栈尺寸不够大
  *@AK_INVALID_PRIORITY 	表示指定的优先级无效
  *@AK_INVALID_PREEMPT  	表示占先参数无效。这个错误发生在连同无占先配置一起时间片被指定
  *@AK_INVALID_START	表示auto_start参数无效
  */
T_hTask AK_Create_Task(void *task_entry, unsigned char *name, unsigned long argc, void *argv,
                        	void *stack_address, unsigned long stack_size, T_OPTION priority, 
                        	unsigned long time_slice, T_OPTION preempt, T_OPTION auto_start);


/*@brief: 列出当前所有AKOS任务的状态
  *@patam prio_format: 0, normal prio; 1, ak_thread prio
  *@patam time_format: 0, ms unit; 1, second unit
  *@return void
  *@retval void
  */
void AK_List_Task(unsigned char prio_format, unsigned char time_format);

/*@brief:此服务删除一个先前定义的任务。参数Task确定需要删除的任务。在这个任务上挂起的任务恢复时返回适当的错误状态。
  *@patam task	[in]任务控制句柄
  *@return long
  *@retval AK_SUCCESS  		表示任务成功删除
  *@retval AK_INVALID_TASK 	表示任务句柄非法
  *@retval AK_INVALID_DELETE  	任务处于一个未完成或未中止状态
  */
long AK_Delete_Task(T_hTask task);


/*
  *@brief:此项服务无条件挂起task指针指定的任务。如果任务已经处于挂起状态。即使在最初导致挂起的条件消失，此服务确仍然保任务保留在挂起状态。AK_Resume_Task用于恢复这种方式的任务挂起。
  *@param  Task	  [in]  任务控制句柄
  *@retval AK_SUCCESS  	表示任务成功完成
  *@retval AK_INVALID_TASK 表示任务句柄非法  
  */
long AK_Suspend_Task(T_hTask task);


/************************************************************************/
 /*@brief:此项服务恢复一个先前通过AK_Suspend_Task服务挂起的任务。		
  *@param  Task	  [in]  任务控制句柄
  *@tetval AK_SUCCESS  表示服务成功完成
  *@retval AK_INVALID_TASK 表示任务句柄无效
  *@retval AK_INVALID_RESUME   表示指定的任务不处于无条件挂起状态。            */          
/************************************************************************/
long AK_Resume_Task(T_hTask task);

/************************************************************************/
/*@brief:此项服务终止task参数指定的任务。
 *@param  Task	  [in]  任务控制句柄
 *@retval AK_SUCCESS  表示服务成功完成
 *@retval AK_INVALID_TASK 表示任务句柄无效 */                               
/************************************************************************/
long AK_Terminate_Task(T_hTask task);

/************************************************************************/
/* @brief:此项服务挂起正在调用任务至指定的定时器节拍数。				*/
/* @param Tick	[in]	挂起的节拍数									*/
/* @return void														*/
/************************************************************************/
void AK_Sleep(unsigned long ticks);


/************************************************************************/
/* @brief:此项服务将CPU让位给其他同一优先级就绪任务。                   */
/************************************************************************/
void AK_Relinquish(void);

/************************************************************************/
/* @biref:此项服务改变指定任务的优先级为包含新优先级的值。				*/
/*		  优先级为从0到255范围的数值。数字越小任务优先级越高。          */
/* @param Task	[in]任务句柄											*/
/* @param new_priority	[in]新的优先级									*/
/* return:此项服务返回调用程序先前的优先级。							*/
/************************************************************************/
T_OPTION AK_Change_Priority(T_hTask task, T_OPTION new_priority);

// ************************************************************************/
// @biref:此项服务返回当前运行的函数指针，也就是调用者的函数指针。*/
// @param void
// return:此项服务返回当前任务的指针*/
//************************************************************************/
T_hTask AK_GetCurrent_Task(void);

/************************************************************************/
/* @brief:此项服务复位先前已终止或结束的任务。							*/
/*																		*/
/* @param:task	[in]任务句柄											*/
/* @param:argc	[in]一个unsigned long数据类型，可以用来传输信息到任务。			*/
/* @argv		[in]一个指针，可以用来传输信息到任务。					*/
/*																		*/
/* retval	AK_SUCCESS			表示服务成功调用						*/
/* retval	AK_INVALID_TASK		表示任务指针无效						*/
/* retval	AK_NOT_TERMINATED	表示指定的任务不是处于终止或完成状态。	*/
/*								只有处于终止或完成状态的任务可以被复位。*/
/*																		*/
/************************************************************************/
long AK_Reset_Task(T_hTask task, unsigned long argc, void *argv);

/************************************************************************/
/* @brief:此项服务查询当前任务的状态                                    */
/* @param:T_hTask	[in]任务的句柄										*/
/*																		*/
/* retval	AK_INVALID_TASK		错误的任务句柄，负数的返回值。其他的任务*/
/*								状态都是正数							*/
/* retval	AK_READY			任务处于运行或就绪状态，可能由于优先级的*/
/*								原因没有执行							*/
/* retval	AK_FINISHED			任务处于完成状态						*/
/* retval	AK_TERMINATED		任务处于被终止状态						*/
/* retval	AK_TASK_SUSPEND		任务处于挂起状态，任务被suspend函数挂起 */
/*								创建后没有运行、sleep自挂起均处于这个状态。*/
/* retval	AK_TASK_WAITING		任务在等待挂起中（队列、信号量、事件集等*/
/*								挂起均在这个状态）						*/
/************************************************************************/
long AK_Task_Status(T_hTask task);

/************************************************************************/
/* @brief:	此项服务检查当前运行的各任务的堆栈使用情况。如果出现栈溢出，*/
/*			则返回0，并输出打印信息，否则返回1                          */
/* @param:	void														*/
/* retval	unsigned long，见brief												*/
/************************************************************************/
unsigned long AK_Check_Task_Stack(void);

/************************************************************************/
/* @brief:	设置任务名，成功则返回0，否则返回 AK_INVALID_TASK           */
/*			              */
/* @param:task	[in]任务句柄											*/
/* @param:name	[in] 任务名，最长支持8字节								*/
/* retval long，见brief												    */
/************************************************************************/
long AK_Set_TaskName(T_hTask task, unsigned char *name);


// Queue Control API
/************************************************************************/
/* @brief:	此服务创建一个消息队列。队列创建支持定长和变长消息的管理。	*/
/*			队列消息由多个unsigned char数据元素组成。                            */
/* @param:	start_address	[in]指定队列的起始地址。					*/
/* @param:	queue_size		[in]指定队列中unsigned char数据元素的总数			*/
/* @param:	message_type	[in]指定队列管理的消息类型。
								AK_FIXED_SIZE表示队列管理定长消息。		
								AK_VARIABLE_SIZE表示队列管理变长尺寸消息*/
/* @param:	message_size	[in]如果队列支持定长消息，这个参数指定每个消
								息的精确长度。如果队列支持变长消息，这个
								参数表示最大消息尺寸。					*/
/* @param:	suspend_type	[in]指定队列挂起类型。此参数有效配置
								为AK_FIFO和AK_PRIORITY，
								分别表示先入先出和优先级顺序挂起。		*/
/* retval	T_hQueue	服务成功完成，返回队列句柄						*/
/* 如果出错，返回如下小于0的错误值*/
/* retval	AK_MEMORY_CORRUPT	申请内存空间失败						*/
/* retval	AK_INVALID_MESSAGE	表示消息类型参数无效					*/
/* retval	AK_INVALID_SIZE	表示指定的消息尺寸大于队列尺寸或为0			*/
/* retval	AK_INVALID_SUSPEND	表示挂起类型参数无效					*/
/* retval	AK_INVALID_SUSPEND	表示挂起类型参数无效					*/
/************************************************************************/
T_hQueue AK_Create_Queue(void *start_address, unsigned long queue_size, 
                      T_OPTION message_type, unsigned long message_size, T_OPTION suspend_type);

/************************************************************************/
/* @brief:	此服务删除一个先前定义的消息队列。参数Queue确定需要删除的	*/
/*			消息队列。在这个队列上挂起的任务恢复时返回一个错误值。		*/
/*			在删除期间和之后，应用程序必须防止队列的使用。              */
/* @param:	suspend_type	[in]队列的句柄								*/
/* retval	AK_SUCCESS	表示成功删除队列
			AK_INVALID_QUEUE	表示队列非法							*/
/************************************************************************/
long AK_Delete_Queue(T_hQueue queue);

/************************************************************************/
/* @brief:	此项服务放置消息到指定的队列底端。如果队列有足够的空间保存消息，
			此项服务立即处理。
			根据队列支持的消息类型，队列消息包括定长或变长unsigned char数据类型数*/
/* @param:	Queue	[in]队列的句柄
			message	[in]发送消息指针
			size	[in]指定消息的unsigned char类型数目
						如果队列支持变长消息，此项参数必须等于或小于队列支持的消息尺寸。
						如果队列支持定长消息，此参数必须正好等于队列支持的消息尺寸。
			Suspend	[in]如果队列已经装满了消息，指定是否挂起调用任务下列挂起配置是有效的
						AK_NO_SUSPEND不管请求是否被满足，服务立即返回。
						注：如果服务从非任务线程调用，这是唯一有效的配置。否则会出错
						AK_SUSPEND	调用任务挂起直到队列空间有效。
						时间间隔值（1 ～ 4294967293）
						调用任务挂起直到一个队列消息放置，或者直到指定数量的时钟节拍到时。*/


/*	retval	AK_SUCCESS			表示服务成功
	retval	AK_INVALID_QUEUE	表示队列非法
	retval	AK_INVALID_POINTER	表示消息指针为空
	retval	AK_INVALID_SIZE		表示size参数不同于队列支持的消息尺寸。只适用于定义定长字节的队列。
	retval	AK_INVALID_SUSPEND	表示试图从非任务线程挂起
	retval	AK_QUEUE_FULL		表示队列为空
	retval	AK_TIMEOUT			表示在挂起到指定超时值之后，队列仍然为空
	retval	AK_QUEUE_DELETE		在任务挂起期间队列被删除				*/
/*注意事项	如果在中断等非任务线程中调用此接口，挂起参数设置不是AK_NO_SUSPEND，则不论队列是否为满，都会返回错误 AK_INVALID_SUSPEND*/
/************************************************************************/
long AK_Send_To_Queue(T_hQueue queue, void *message, unsigned long size, unsigned long suspend);

/************************************************************************/
/* @brief:	此项服务放置消息到指定的队列前端。如果队列有足够的空间保存消息，
			此项服务立即处理。
			根据队列支持的消息类型，队列消息由定长或不定长字节组成。*/

/* @param:	Queue	[in]队列的句柄
			message	[in]发送消息指针
			size	[in]指定消息的unsigned char类型数目
						如果队列支持变长消息，此项参数必须等于或小于队列支持的消息尺寸。
						如果队列支持定长消息，此参数必须正好等于队列支持的消息尺寸。
			Suspend	[in]如果队列已经装满了消息，指定是否挂起调用任务下列挂起配置是有效的
						AK_NO_SUSPEND不管请求是否被满足，服务立即返回。
						注：如果服务从非任务线程调用，这是唯一有效的配置。否则会出错
						AK_SUSPEND	调用任务挂起直到队列空间有效。
						时间间隔值（1 ～ 4294967293）
						调用任务挂起直到一个队列消息放置，或者直到指定数量的时钟节拍到时。*/


/*	retval	AK_SUCCESS			表示服务成功
	retval	AK_INVALID_QUEUE	表示队列非法
	retval	AK_INVALID_POINTER	表示消息指针为空
	retval	AK_INVALID_SIZE		表示size参数不同于队列支持的消息尺寸。只适用于定义定长字节的队列。
	retval	AK_INVALID_SUSPEND	表示试图从非任务线程挂起
	retval	AK_QUEUE_FULL		表示队列为空
	retval	AK_TIMEOUT			表示在挂起到指定超时值之后，队列仍然为空
	retval	AK_QUEUE_DELETE		在任务挂起期间队列被删除				*/

/*注意事项	如果在中断等非任务线程中调用此接口，挂起参数设置不是AK_NO_SUSPEND，则不论队列是否为满，都会返回错误 AK_INVALID_SUSPEND*/
/************************************************************************/
long AK_Send_To_Front_of_Queue(T_hQueue queue, void *message, unsigned long size, unsigned long suspend);

/************************************************************************/
/* @brief:	此项服务广播一个消息到从指定的队列等待消息的所有任务。
			如果没有任务在等待，消息只是放到队列末端。
			根据队列的创建，队列消息由定长或不定长字节组成。
   @param:	Queue	队列的句柄
			message	发送消息指针
			size	指定消息的unsigned char类型数目
					如果队列支持变长消息，此项参数必须等于或小于队列支持的消息尺寸。
					如果队列支持定长消息，此参数必须正好等于队列支持的消息尺寸。
			Suspend	如果队列已经包含了一个消息，指定是否挂起调用任务
					AK_NO_SUSPEND
						不管请求是否满足服务立即返回。
					AK_SUSPEND
						调用任务挂起直到消息被拷贝入队列。
					时间间隔值（1 ～ 4294967293）
						调用任务挂起直到消息拷贝入队列或者直到指定的定时器节拍到时。

返回值说明	
	AK_SUCCESS			表示服务成功
	AK_INVALID_QUEUE	表示队列无效
	AK_INVALID_POINTER	表示消息指针为AK_NULL
	AK_INVALID_SIZE		表示消息尺寸与队列支持的消息尺寸不匹配
	AK_INVALID_SUSPEND	表示试图从非任务线程挂起
	AK_QUEUE_FULL		表示队列满
	AK_TIMEOUT			表示即使在挂起超时之后，队列状态仍然为满
	AK_QUEUE_DELETE		任务在挂起期间队列被删除

注意事项	如果在中断等非任务线程中调用此接口，挂起参数设置不是AK_NO_SUSPEND，
			则不论队列是否为满，都会返回错误 AK_INVALID_SUSPEND			*/
/************************************************************************/
long AK_Broadcast_To_Queue(T_hQueue queue, void *message, unsigned long size, unsigned long suspend);

/************************************************************************/
/* @brief:	此项服务从指定的队列中接收一个消息。如果队列包含一个或多个消息，
			立即从队列里移除前面的消息且拷贝到指定的位置。				*/
/* @param:	Queue	[in]队列的句柄										*/
/*			message	[in]消息目的指针。注：消息目标必须足够大能容纳size的字节数。*/
/*			size	[in]指定消息内的unsigned char数据类型数。
						这个值必须对应于在队列创建时定义的消息尺寸。
						只适用于定义定长字节的队列；否则忽略。			*/
/*			actual_size	[out]指向保存接收消息实际unsigned char数据类型数的变量的指针。	
						注意：这里是指针，是输出项，而上一个size是输入项	*/
/*			Suspend	[in]如果队列为空，指定是否挂起正在调用的任务。
						下面是挂起类型的有效选项：
						AK_NO_SUSPEND
						不管请求是否满足，服务立即返回。
						注：如果服务被非任务线程调用，这是唯一有效的配置。否则发生错误
						AK_SUSPEND
						正在调用的任务挂起直到有新消息到来。
						时间间隔值（1~4294967293）
						正在调用的服务挂起直到消息有效或直到指定的定时器节拍数到时*/

/*	retval	AK_SUCCESS			表示服务成功
	retval	AK_INVALID_QUEUE	表示队列非法
	retval	AK_INVALID_POINTER	表示消息指针为空或者actual_size指针为空
	retval	AK_INVALID_SIZE		表示size参数不同于队列支持的消息尺寸。只适用于定义定长字节的队列。
	retval	AK_INVALID_SUSPEND	表示试图从非任务线程挂起
	retval	AK_QUEUE_EMPTY		表示队列为空
	retval	AK_TIMEOUT			表示在挂起到指定超时值之后，队列仍然为空
	retval	AK_QUEUE_DELETE		在任务挂起期间队列被删除				*/
/************************************************************************/
long AK_Receive_From_Queue(T_hQueue queue, void *message, unsigned long size,
                                unsigned long *actual_size, unsigned long suspend);

/************************************************************************/
/* @brief:	此项服务放置消息到指定的队列低端。首先对队列中已经有的消息进行比较，
			如果已经有了通过回调函数Function的消息，则不再放入。
			如果没有相同消息，且队列有足够的空间保存消息，此项服务立即处理。
			此项服务目前只支持定长队列。								*/
/* @param:
	Queue	[in]队列的句柄
	message	[in]发送消息指针
	size	[in]指定消息的unsigned long类型数目
			如果队列支持变长消息，此项参数必须等于或小于队列支持的消息尺寸。
			如果队列支持定长消息，此参数必须正好等于队列支持的消息尺寸。
	Suspend	[in]如果队列已经包含了一个消息，指定是否挂起调用任务
			下列挂起配置是有效的
			AK_NO_SUSPEND不管请求是否被满足，服务立即返回。
			注：如果服务从非任务线程调用，这是唯一有效的配置。
			AK_SUSPEND	调用任务挂起直到队列空间有效。
			时间间隔值（1 ～ 4294967293）调用任务挂起直到一个队列消息放置，
										或者直到指定数量的时钟节拍到时。
	Function[in]进行比较的回调函数。预定比较结果：如果比较结果相同返回AK_TRUE，如果比较结果不同返回AK_FALSE。*/

/* @retval:
	AK_SUCCESS			成功发送消息到队列
	AK_INVALID_QUEUE	表示队列无效
	AK_EXIST_MESSAGE	表示已经有相同的消息存在
	AK_INVALID_POINTER	表示消息指针为AK_NULL
	AK_INVALID_SIZE		表示消息尺寸与队列支持的消息尺寸不匹配
	AK_INVALID_SUSPEND	表示试图从非任务线程挂起
	AK_QUEUE_FULL		表示队列满
	AK_TIMEOUT			表示即使在挂起超时之后，队列状态仍然为满
	AK_QUEUE_DELETE		任务在挂起期间队列被删除*/
/*注意事项	如果在中断等非任务线程中调用此接口，挂起参数设置不是AK_NO_SUSPEND，
			则不论队列是否为满，都会返回错误 AK_INVALID_SUSPEND*/
/************************************************************************/
long AK_Send_Unique_To_Queue(T_hQueue queue, void *message, unsigned long size, 
                                    unsigned long suspend, CallbakCompare Function);

/************************************************************************/
/* @brief:	此项服务放置消息到指定的队列顶端。
			首先对队列中已经有的消息进行比较，如果已经有了和message相同的消息，则不再放入。
			如果没有相同消息，且队列有足够的空间保存消息，此项服务立即处理。
			此项服务的具体功能可以参考AK_Send_To_Front_of_Queue。此项服务目前只支持定长队列。
   @param
	Queue	[in]队列的句柄
	message	[in]发送消息指针
	size	[in]指定消息的unsigned long类型数目
			如果队列是变长消息都列，此项参数必须等于或小于队列支持的消息尺寸。
			如果队列是定长消息，此参数必须正好等于队列支持的消息尺寸。
	Suspend	[in]如果队列已经包含了一个消息，指定是否挂起调用任务
			下列挂起配置是有效的
			AK_NO_SUSPEND不管请求是否被满足，服务立即返回。
			注：如果服务从非任务线程调用，这是唯一有效的配置。
			AK_SUSPEND	调用任务挂起直到队列空间有效。
			时间间隔值（1 ～ 4294967293）调用任务挂起直到一个队列消息放置，
										或者直到指定数量的时钟节拍到时。
	Function[in]进行比较的回调函数。
				预定比较结果：如果比较结果相同返回AK_TRUE，如果比较结果不同返回AK_FALSE。*/

/*返回值说明	
	AK_SUCCESS			成功发送消息到队列
	AK_INVALID_QUEUE	表示队列无效
	AK_EXIST_MESSAGE	表示已经有相同的消息存在
	AK_INVALID_POINTER	表示消息指针为AK_NULL
	AK_INVALID_SIZE		表示消息尺寸与队列支持的消息尺寸不匹配
	AK_INVALID_SUSPEND	表示试图从非任务线程挂起
	AK_QUEUE_FULL		表示队列满
	AK_TIMEOUT			表示即使在挂起超时之后，队列状态仍然为满
	AK_QUEUE_DELETE		任务在挂起期间队列被删除*/
/*注意事项	如果在中断等非任务线程中调用此接口，挂起参数设置不是AK_NO_SUSPEND，
			则不论队列是否为满，都会返回错误 AK_INVALID_SUSPEND*/
/************************************************************************/
long AK_Send_Unique_To_Front_of_Queue(T_hQueue queue_ptr, void *message, 
                                    unsigned long size, unsigned long suspend, CallbakCompare Function);

/************************************************************************/
/* @brief:此项服务返回已经建立的消息队列数量							*/
/************************************************************************/
unsigned long AK_Established_Queues(void);

/************************************************************************/
/* @brief:此项服务重置queue指定的队列，所有在队列上
				挂起的任务返回适当的错误值*/
/* @param:	queue	[in]队列的句柄*/
/*返回值说明	
	AK_SUCCESS			成功发送消息到队列
	AK_INVALID_QUEUE	表示队列无效*/
/************************************************************************/
long AK_Reset_Queue(T_hQueue queue);

// Mailbox API

T_hMailbox AK_Create_Mailbox(T_OPTION suspend_type);

long AK_Delete_Mailbox(T_hMailbox mailbox);

long AK_Broadcast_To_Mailbox(T_hMailbox mailbox, unsigned long *message, T_OPTION suspend_type);

long AK_Receive_From_Mailbox(T_hMailbox mailbox, unsigned long *message, T_OPTION suspend_type);

long AK_Send_To_Mailbox(T_hMailbox mailbox, unsigned long *message, T_OPTION suspend_type);

unsigned long AK_Established_Mailboxes(void);

// Semaphore Control API

/************************************************************************/
/* @brief:	此项服务创建一个计数信号量。信号量值范围0～4294967294。		*/
/* @param:	initial_count	[in]指定信号量的初始值
			supend_type		[in]指定任务挂起类型。
							此参数有效配置为AK_FIFO和AK_PRIORITY，
							分别表示先入先出和优先级顺序挂起。*/

/*返回值说明	
	T_hSemaphore		表示成功创建信号量，返回句柄
	AK_INVALID_SUSPEND	表示挂起类型参数无效*/
/************************************************************************/
T_hSemaphore AK_Create_Semaphore(unsigned long initial_count, T_OPTION suspend_type);

/************************************************************************/
/* @brief	此服务删除一个先前创建的信号量。
			参数Semaphore确定需要删除的信号量。
			在这个信号量上挂起的任务恢复时返回适当的错误状态。
			在删除期间和之后，应用程序必须防止信号量的使用。*/
/* @param	semaphore	指定信号量的句柄								*/
/*返回值说明	
	AK_SUCCESS	表示服务成功完成
	AK_INVALID_SEMAPHORE	表示信号量句柄非法*/
/************************************************************************/
long AK_Delete_Semaphore(T_hSemaphore semaphore);

/************************************************************************/
/* @brief:	此项服务获得指定信号量的实例。一旦实例通过内部计数器实现，
			获得一个信号量转化为消耗该信号量，内部计数器减一。
			如果信号量计数器在这个调用之前为0，服务不能满足。			*/
/* @param	semaphore	[in]指定信号量的句柄
			suspend		[in]如果信号量不能被获得（当前为0），
			指定正在调用的任务是否挂起。下列挂起类型有效：
				AK_NO_SUSPEND	不管请求是否满足，服务立即返回。
					注：如果服务从一个非任务线程被调用，这是唯一有效的配置。
				AK_SUSPEND	正在调用的任务挂起直到信号量可以被获得。
				时间间隔值（1～4294967293）正在调用任务挂起
					直到信号量可以被获得或者指定的定时器节拍值到时。*/
/* 返回值说明
	AK_SUCCESS				表示服务成功完成
	AK_INVALID_SEMAPHORE	表示信号量句柄非法
	AK_INVALID_SUSPEND		表示试图从一个非任务线程挂起
	AK_UNAVAILABLE			表示信号量难以获得
	AK_TIMEOUT				表示甚至在挂起指定的时间间隔后信号量仍然难以获得
	AK_SEMAPHORE_DELETE		在任务挂起期间信号量被删除*/
/*注意事项	如果在中断等非任务线程中调用此接口，挂起参数设置不是AK_NO_SUSPEND，
			则不论能否获得信号量，都会返回错误 AK_INVALID_SUSPEND*/
/************************************************************************/
long AK_Obtain_Semaphore(T_hSemaphore semaphore, unsigned long suspend);

/************************************************************************/
/* @brief:	此项服务释放由参数semaphore指定的信号量的一个实例。
			如果有很多任务等待获得同一个信号量，获得信号
			量的任务由create信号量时候的AK_PRIORITY或AK_FIFO决定。
			若是AK_PRIORITY就是优先级高的任务获得，若是FIFO
			就是先挂起的任务先得。	另外，如果没有任务等待
			这个信号量，内部计数器加一。			*/
/* @param:	semaphore	[in]指定信号量的句柄							*/
/*返回值说明
	AK_SUCCESS	表示服务成功完成
	AK_INVALID_SEMAPHORE	表示信号量句柄非法							*/
/*note: 即使成功释放信号量，信号量也不会大于初始值*/
/************************************************************************/
long AK_Release_Semaphore(T_hSemaphore semaphore);

/************************************************************************/
/* @brief:	此项服务重置由参数semaphore指定的信号量。
			所有在此信号量上挂起的任务将获得适当的返回值				*/
/* @param:	semaphore	[in]指定信号量的句柄							*/
/*返回值说明
	AK_SUCCESS	表示服务成功完成
	AK_INVALID_SEMAPHORE	表示信号量句柄非法							*/
/************************************************************************/
long AK_Reset_Semaphore(T_hSemaphore semaphore, unsigned long initial_count);

//EventGroup API
T_hEventGroup AK_Create_Event_Group(void);

long AK_Delete_Event_Group(T_hEventGroup eventgroup);

long AK_Retrieve_Events(T_hEventGroup eventgroup, unsigned long requested_events, 
                        T_OPTION operation, unsigned long *retrieved_events, unsigned long suspend);

long AK_Set_Events(T_hEventGroup eventgroup, unsigned long event_flags, T_OPTION operation);

unsigned long AK_Established_Event_Groups(void);

// Timer API
T_hTimer AK_Create_Timer(void (*expiration_routine)(unsigned long), unsigned long id, 
                    unsigned long initial_time, unsigned long reschedule_time, T_OPTION enable);
                    
long AK_Control_Timer(T_hTimer timer, T_OPTION enable);

long AK_Delete_Timer(T_hTimer timer);

// Interrupt API
/************************************************************************/
/* @brief:	此项服务创建一个高级中断服务子程序（HISR）。
			HISRs允许被大多数的akos服务调用，不像低级中断服务子程序（LISR）。*/
/* @param:	
	hisr_entry	[in]指定HISR的函数入口点
	name		[in]HISR名字符串指针，最长只有8字节
	priority	[in]有三个HISR优先级（0－2）。优先级0为最高
	stack_pointer	[in]HISR的堆栈区指针。每个HISR有它自己的堆栈区。
					注意HISR堆栈已经被调用者分配过。
	stack_size	[in]HISR堆栈的字节数									*/
/*返回值说明
	AK_SUCCESS	表示服务成功完成
	AK_MEMORY_CORRUPT	表示内存申请失败
	AK_INVALID_ENTRY	表示HISR入口指针为空
	AK_INVALID_PRIORITY	表示HISR优先级为空
	AK_INVALID_MEMORY	表示堆栈指针为空
	AK_INVALID_SIZE	表示堆栈尺寸太小									*/
/************************************************************************/
T_hHisr AK_Create_HISR(void (*hisr_entry)(void), unsigned char *name, 
                          T_OPTION priority, void *stack_address, unsigned long stack_size);
/************************************************************************/
/* @brief:	本服务激活由hisr指针指向的HISR。如果指定的HISR正在运行，
			这次激活请求在当前运行结束之前不会处理。
			对每次激活请求，HISR运行一次。*/
/* @param:	hisr	[in]HISR的句柄										*/
/*返回值说明
	AK_SUCCESS	表示服务成功完成
	AK_INVALID_HISR	表示HISR句柄非法									*/
/************************************************************************/
long AK_Activate_HISR(T_hHisr hisr);

/************************************************************************/
/* @brief:	此服务删除一个先前创建的HISR，
			参数hisr确定需要删除的HISR。
			在删除期间和之后，应用程序必须防止HISR的使用。*/
/* @param:	hisr	[in]HISR的句柄										*/
/*返回值说明
	AK_SUCCESS	表示服务成功完成
	AK_INVALID_HISR	表示HISR句柄非法									*/
/************************************************************************/
long AK_Delete_HISR(T_hHisr hisr);

/************************************************************************/
/* @brief:	此项服务使被vector指定的中断向量和被list_entry
			指向LISR函数联合起来。在调用指定的LISR之前系统
			上下文自动保存并且在LISR返回之后恢复。因此，
			LISR函数可以用C语言编写。然而，LISRs只允许访问
			少量的AKOS服务。如果必须和其他任务进程的交流，
			必须激活一个高优先级的中断服务子程序（HISR）*/
/* @param
	vector		[in]中断向量
	list_entry	[in]中断向量指向的函数体
	old_lisr	[out]指向旧有函数题的指针的指针							*/

/*返回值说明
	AK_SUCCESS	表示服务成功完成
	AK_INVALID_VECTOR	表示指定的向量无效
	AK_NOT_REGISTERED	表示向量当前没有注册且分别注册由lisr_entry指定
				(Indicates the vector is not registered and de-registration was specified by lisr_entry.)
	AK_NO_MORE_LISRS	表示已注册LISRs的最大数已经超出了。最大
	数在启动项头文件中更改。如果更改需要重建库文件*/

/*注意事项	警告:如果一个LISR用汇编语言编写，
	它必须遵循C编译器关于寄存器用法和返回机制的约定。*/
/************************************************************************/
long AK_Register_LISR(long vector, void (*list_entry)(long), 
							void (**old_lisr)(long));

/************************************************************************/
/* @brief:	此项服务使用调用者（参数new）自定义
			中断服务子程序代替vector指定的中断向量。
			服务返回先前中断向量内容。

警告：提供这个子程序的ISRs用汇编语言编写，
		负责存储和恢复任何使用的寄存器。
		一些端口有一些附加约束强加在这些ISRs上。
		请看附加指定目标信息的指定处理器端口要求。
参数说明
	vector	[in]中断向量
	new		[in]新的中断服务子程序
                                                                     */
/************************************************************************/
void *AK_Setup_Vector(long vector, void *new_vector);

/************************************************************************/
/* @brief:	此项服务获取当前已经建立的高级中断数量*/
/************************************************************************/
unsigned long AK_Established_HISRs(void);


/******************************************************************************************************
**                              use example
**		1   call    AK_feed_watchdog( food)   //call in you thread it will start thread watchodg
**      2   close watchdog   call 	AK_feed_watchdog( 0 )   
**		  
*******************************************************************************************************/

/*************************************************************
*这两个是驱动保护接口，可能引起系统异常，慎用。
**************************************************************/
void AK_Drv_Protect(void);
void AK_Drv_Unprotect(void);

/*****************************************************************************************************
* @author Yao Hongshi
* @date 2007-11-06
* @param unsigned int food
* @return STATUS  -- it has two status, one is zero ,ir present watchdog gets well
*                            the  other is  (-1), it present food is illegal
* @brief: watch dog handler of theard ,here it will check watchdog_counter in TCB(or HCB),
* @   wether it has been underflow , if it is right, here will awake up watchdog_HISR. or
* @  it will decrease watchdog_counter,and return.
*******************************************************************************************************/

 typedef  struct locale
 {
	 long			   error_type;
	 char			   tc_name[8+4];			 //task or HISR 's name
	 
	 void 		   *tc_stack_start; 		 // Stack starting address
	 void 		   *tc_stack_end;			 // Stack ending address 
	 void 		   *tc_stack_pointer;		 // HISR or Task stack pointer	 
	 unsigned long				tc_stack_size;			 // HISR or Task stack's size	 
	 
	 unsigned long				tc_pc_value;			 //thread current PC value
	 
	 unsigned long				reg[13];
	 
	 
	 unsigned long				tc_current_sp;
	 unsigned long				stack_current_value[20];
	 
	 unsigned long				func_caller;

	 char *				feed_file;
	 unsigned long				feed_line;
#ifdef		FUNC_ENTRY_MODULE
	 unsigned long				entry_function_adrress;  
#endif
	 
 } THREAD_LOCALE;
 
typedef void (*T_WD_CB)(void* pData); 

#define AK_Feed_Watchdog(x)	AK_Feed_WatchdogEx(x, (T_pSTR)(__FILE__),(unsigned long)(__LINE__))
long AK_Feed_WatchdogEx(unsigned long  food, char * filename, unsigned long line);

void AK_Set_WD_Callback(T_WD_CB cb);

unsigned long AK_System_Init(void *task_entry, unsigned char *name, void *stack_address, unsigned long stack_size);

void  AK_System_Protect(void);

void AK_System_Unprotect(void);


#endif
