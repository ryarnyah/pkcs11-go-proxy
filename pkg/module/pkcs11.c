#include <string.h>

#include "../pkcs11/pkcs11go.h"

#ifdef PKCS11_THREAD_LOCKING
#if defined(HAVE_PTHREAD)
#include <pthread.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#endif /* PKCS11_THREAD_LOCKING */

#ifdef PKCS11_THREAD_LOCKING

#if defined(HAVE_PTHREAD)

CK_RV mutex_create(void **mutex)
{
	pthread_mutex_t *m;

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return CKR_GENERAL_ERROR;;
	pthread_mutex_init(m, NULL);
	*mutex = m;
	return CKR_OK;
}

CK_RV mutex_lock(void *p)
{
	if (pthread_mutex_lock((pthread_mutex_t *) p) == 0)
		return CKR_OK;
	else
		return CKR_GENERAL_ERROR;
}

CK_RV mutex_unlock(void *p)
{
	if (pthread_mutex_unlock((pthread_mutex_t *) p) == 0)
		return CKR_OK;
	else
		return CKR_GENERAL_ERROR;
}

CK_RV mutex_destroy(void *p)
{
	pthread_mutex_destroy((pthread_mutex_t *) p);
	free(p);
	return CKR_OK;
}

static CK_C_INITIALIZE_ARGS _def_locks = {
	mutex_create, mutex_destroy, mutex_lock, mutex_unlock, 0, NULL };
#define HAVE_OS_LOCKING

#elif defined(_WIN32)

CK_RV mutex_create(void **mutex)
{
	CRITICAL_SECTION *m;

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return CKR_GENERAL_ERROR;
	InitializeCriticalSection(m);
	*mutex = m;
	return CKR_OK;
}

CK_RV mutex_lock(void *p)
{
	EnterCriticalSection((CRITICAL_SECTION *) p);
	return CKR_OK;
}


CK_RV mutex_unlock(void *p)
{
	LeaveCriticalSection((CRITICAL_SECTION *) p);
	return CKR_OK;
}


CK_RV mutex_destroy(void *p)
{
	DeleteCriticalSection((CRITICAL_SECTION *) p);
	free(p);
	return CKR_OK;
}

static CK_C_INITIALIZE_ARGS _def_locks = {
	mutex_create, mutex_destroy, mutex_lock, mutex_unlock, 0, NULL };
#define HAVE_OS_LOCKING

#endif

#endif /* PKCS11_THREAD_LOCKING */

static CK_C_INITIALIZE_ARGS_PTR	global_locking;
static void *global_lock = NULL;
#ifdef HAVE_OS_LOCKING
static CK_C_INITIALIZE_ARGS_PTR default_mutex_funcs = &_def_locks;
#else
static CK_C_INITIALIZE_ARGS_PTR default_mutex_funcs = NULL;
#endif

/*
 * Locking functions
 */

CK_RV
sc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args)
{
	CK_RV rv = CKR_OK;

	int applock = 0;
	int oslock = 0;
	if (global_lock)
		return CKR_OK;

	/* No CK_C_INITIALIZE_ARGS pointer, no locking */
	if (!args)
		return CKR_OK;

	if (args->pReserved != NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	/* If the app tells us OS locking is okay,
	 * use that. Otherwise use the supplied functions.
	 */
	global_locking = NULL;
	if (args->CreateMutex && args->DestroyMutex &&
		   args->LockMutex   && args->UnlockMutex) {
			applock = 1;
	}
	if ((args->flags & CKF_OS_LOCKING_OK)) {
		oslock = 1;
	}

	/* Based on PKCS#11 v2.11 11.4 */
	if (applock && oslock) {
		/* Shall be used in threaded environment, prefer app provided locking */
		global_locking = args;
	} else if (!applock && oslock) {
		/* Shall be used in threaded environment, must use operating system locking */
		global_locking = default_mutex_funcs;
	} else if (applock && !oslock) {
		/* Shall be used in threaded environment, must use app provided locking */
		global_locking = args;
	} else if (!applock && !oslock) {
		/* Shall not be used in threaded environment, use operating system locking */
		global_locking = default_mutex_funcs;
	}

	if (global_locking != NULL) {
		/* create mutex */
		rv = global_locking->CreateMutex(&global_lock);
	}

	return rv;
}

CK_RV sc_pkcs11_lock(void)
{
	if (!global_lock)
		return CKR_OK;
	if (global_locking)  {
		while (global_locking->LockMutex(global_lock) != CKR_OK)
			;
	}

	return CKR_OK;
}

static void
__sc_pkcs11_unlock(void *lock)
{
	if (!lock)
		return;
	if (global_locking) {
		while (global_locking->UnlockMutex(lock) != CKR_OK)
			;
	}
}

void sc_pkcs11_unlock(void)
{
	__sc_pkcs11_unlock(global_lock);
}

/*
 * Free the lock - note the lock must be held when
 * you come here
 */
void sc_pkcs11_free_lock(void)
{
	void	*tempLock;

	if (!(tempLock = global_lock))
		return;

	/* Clear the global lock pointer - once we've
	 * unlocked the mutex it's as good as gone */
	global_lock = NULL;

	/* Now unlock. On SMP machines the synchronization
	 * primitives should take care of flushing out
	 * all changed data to RAM */
	__sc_pkcs11_unlock(tempLock);

	if (global_locking)
		global_locking->DestroyMutex(tempLock);
	global_locking = NULL;
}

CK_RV goInitialize(void);
CK_RV goFinalize(void);
CK_RV goGetInfo(ckInfoPtr);
CK_RV goGetSlotList(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
CK_RV goGetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR);
CK_RV goGetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
CK_RV goGetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
CK_RV goGetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
CK_RV goInitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV goSetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV goOpenSession(CK_SLOT_ID, CK_FLAGS, CK_SESSION_HANDLE_PTR);
CK_RV goCloseSession(CK_SESSION_HANDLE);
CK_RV goCloseAllSessions(CK_SLOT_ID);
CK_RV goGetSessionInfo(CK_SESSION_HANDLE,CK_SESSION_INFO_PTR);
CK_RV goGetOperationState(CK_SESSION_HANDLE , CK_BYTE_PTR , CK_ULONG_PTR);
CK_RV goSetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR , CK_ULONG , CK_OBJECT_HANDLE , CK_OBJECT_HANDLE );
CK_RV goLogin(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
CK_RV goLogout(CK_SESSION_HANDLE);
CK_RV goCreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR , CK_ULONG , CK_OBJECT_HANDLE_PTR );
CK_RV goCopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE ,CK_ATTRIBUTE_PTR , CK_ULONG ,CK_OBJECT_HANDLE_PTR );
CK_RV goDestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE );
CK_RV goGetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);
CK_RV goGetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV goSetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV goFindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
CK_RV goFindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
CK_RV goFindObjectsFinal(CK_SESSION_HANDLE);
CK_RV goEncryptInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goEncrypt(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goEncryptFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goDecrypt(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDigestInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR);
CK_RV goDigest(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDigestUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goDigestKey(CK_SESSION_HANDLE,CK_OBJECT_HANDLE);
CK_RV goDigestFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goSignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
CK_RV goSignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
CK_RV goSign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV goSignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV goSignRecoverInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goSignRecover(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goVerifyInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goVerify(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG);
CK_RV goVerifyUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goVerifyFinal(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goVerifyRecoverInit(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE);
CK_RV goVerifyRecover(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDigestEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptDigestUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goSignEncryptUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goDecryptVerifyUpdate(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goGenerateKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV goGenerateKeyPair(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_ATTRIBUTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR,CK_OBJECT_HANDLE_PTR);
CK_RV goWrapKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG_PTR);
CK_RV goUnwrapKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_BYTE_PTR,CK_ULONG,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV goDeriveKey(CK_SESSION_HANDLE,CK_MECHANISM_PTR,CK_OBJECT_HANDLE,CK_ATTRIBUTE_PTR,CK_ULONG,CK_OBJECT_HANDLE_PTR);
CK_RV goSeedRandom(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goGenerateRandom(CK_SESSION_HANDLE,CK_BYTE_PTR,CK_ULONG);
CK_RV goWaitForSlotEvent(CK_FLAGS,CK_SLOT_ID_PTR,CK_VOID_PTR);
void goLog(const char*);

CK_FUNCTION_LIST pkcs11_functions = 
{
	{2, 20},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

// We have to match the PKCS#11 API exactly here, but many of the parameters
// aren't passed to Go (either because they're unsupported features, or they're
// reserved.)  Don't trigger compiler warrnings about this.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (NULL != pInitArgs && ((CK_C_INITIALIZE_ARGS_PTR)pInitArgs)->pReserved != NULL) {
		return CKR_ARGUMENTS_BAD;
	}
	CK_RV rv;
	rv = sc_pkcs11_init_lock((CK_C_INITIALIZE_ARGS_PTR) pInitArgs);
	if (rv != CKR_OK) {
		return CKR_ARGUMENTS_BAD;
	}
	rv = goInitialize();
	if (rv != CKR_OK) {
		/* Release and destroy the mutex */
		sc_pkcs11_free_lock();
	}
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (NULL != pReserved) {
		return CKR_ARGUMENTS_BAD;
	}
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goFinalize();

	/* Release and destroy the mutex */
	sc_pkcs11_free_lock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	// Handle packing compatibility for Go.
	// Based on CK_RV GetInfo in pkcs11.go from miekg/pkcs11

	ckInfo goInfo;
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetInfo(&goInfo);

	sc_pkcs11_unlock();

	pInfo->cryptokiVersion = goInfo.cryptokiVersion;
	memcpy(pInfo->manufacturerID, goInfo.manufacturerID, sizeof(pInfo->manufacturerID));
	pInfo->flags = goInfo.flags;
	memcpy(pInfo->libraryDescription, goInfo.libraryDescription, sizeof(pInfo->libraryDescription));
	pInfo->libraryVersion = goInfo.libraryVersion;

	return rv;
}


// Export in Windows DLL's (workaround for change introduced by
// https://github.com/golang/go/issues/30674 ).
#ifdef _WIN32
	__declspec(dllexport)
#endif
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetSlotList(tokenPresent, pSlotList, pulCount);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetSlotInfo(slotID, pInfo);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetTokenInfo(slotID, pInfo);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetMechanismList(slotID, pMechanismList, pulCount);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetMechanismInfo(slotID, type, pInfo);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goInitPIN(hSession, pPin, ulPinLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goOpenSession(slotID, flags, phSession);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goCloseSession(hSession);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{	
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goCloseAllSessions(slotID);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetSessionInfo(hSession, pInfo);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetOperationState(hSession, pOperationState, pulOperationStateLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{

	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSetOperationState(hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goLogin(hSession, userType, pPin, ulPinLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{	
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goLogout(hSession);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goCreateObject(hSession, pTemplate, ulCount, phObject);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goCopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDestroyObject(hSession, hObject);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetObjectSize(hSession, hObject, pulSize);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGetAttributeValue(hSession, hObject, pTemplate, ulCount);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSetAttributeValue(hSession, hObject, pTemplate, ulCount);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goFindObjectsInit(hSession, pTemplate, ulCount);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goFindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goFindObjectsFinal(hSession);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goEncryptInit(hSession, pMechanism, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goEncrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goEncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDecryptInit(hSession, pMechanism, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDecrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDecryptFinal(hSession, pLastPart, pulLastPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDigestInit(hSession, pMechanism);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDigest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDigestUpdate(hSession, pPart, ulPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDigestKey(hSession, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDigestFinal(hSession, pDigest, pulDigestLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSignInit(hSession, pMechanism, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSignUpdate(hSession, pPart, ulPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSignFinal(hSession, pSignature, pulSignatureLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSignRecoverInit(hSession, pMechanism, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goVerifyInit(hSession, pMechanism, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goVerify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goVerifyUpdate(hSession, pPart, ulPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goVerifyFinal(hSession, pSignature, ulSignatureLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goVerifyRecoverInit(hSession, pMechanism, hKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goVerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goWrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goUnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goDeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goSeedRandom(hSession, pSeed, ulSeedLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goGenerateRandom(hSession, RandomData, ulRandomLen);
	sc_pkcs11_unlock();
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	CK_RV rv;
	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = goWaitForSlotEvent(flags, pSlot, pReserved);
	sc_pkcs11_unlock();
	return rv;
}

#pragma GCC diagnostic pop
