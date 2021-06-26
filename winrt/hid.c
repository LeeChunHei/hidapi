/*******************************************************
 HIDAPI - Multi-Platform library for
 communication with HID devices.

 Alan Ott
 Signal 11 Software

 8/22/2009

 Copyright 2009, All Rights Reserved.
 
 At the discretion of the user of this library,
 this software may be licensed under the terms of the
 GNU General Public License v3, a BSD-Style license, or the
 original HIDAPI license as outlined in the LICENSE.txt,
 LICENSE-gpl3.txt, LICENSE-bsd.txt, and LICENSE-orig.txt
 files located at the root of the source distribution.
 These files may also be found in the public source
 code repository located at:
        https://github.com/libusb/hidapi .
********************************************************/

#include <windows.h>

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

#ifdef __MINGW32__
#include <ntdef.h>
#include <winbase.h>
#endif

#ifdef __CYGWIN__
#include <ntdef.h>
#define _wcsdup wcsdup
#endif

/* The maximum number of characters that can be passed into the
   HidD_Get*String() functions without it failing.*/
#define MAX_STRING_WCHARS 0xFFF

/*#define HIDAPI_USE_DDK*/

#ifdef __cplusplus
extern "C" {
#endif
	#include <setupapi.h>
	#include <winioctl.h>
	#ifdef HIDAPI_USE_DDK
		#include <hidsdi.h>
	#endif

	/* Copied from inc/ddk/hidclass.h, part of the Windows DDK. */
	#define HID_OUT_CTL_CODE(id)  \
		CTL_CODE(FILE_DEVICE_KEYBOARD, (id), METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
	#define IOCTL_HID_GET_FEATURE                   HID_OUT_CTL_CODE(100)
	#define IOCTL_HID_GET_INPUT_REPORT              HID_OUT_CTL_CODE(104)

#ifdef __cplusplus
} /* extern "C" */
#endif

#include <stdio.h>
#include <stdlib.h>


#include "hidapi.h"

#include "winrt/windows.devices.enumeration.h"
#include "winrt/windows.devices.humaninterfacedevice.h"

#undef MIN
#define MIN(x,y) ((x) < (y)? (x): (y))

#ifdef _MSC_VER
	/* Thanks Microsoft, but I know how to use strncpy(). */
	#pragma warning(disable:4996)
#endif

#ifdef __cplusplus
extern "C" {
#endif

static struct hid_api_version api_version = {
	.major = HID_API_VERSION_MAJOR,
	.minor = HID_API_VERSION_MINOR,
	.patch = HID_API_VERSION_PATCH
};

#ifndef HIDAPI_USE_DDK
	/* Since we're not building with the DDK, and the HID header
	   files aren't part of the SDK, we have to define all this
	   stuff here. In lookup_functions(), the function pointers
	   defined below are set. */
	typedef struct _HIDD_ATTRIBUTES{
		ULONG Size;
		USHORT VendorID;
		USHORT ProductID;
		USHORT VersionNumber;
	} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

	typedef USHORT USAGE;
	typedef struct _HIDP_CAPS {
		USAGE Usage;
		USAGE UsagePage;
		USHORT InputReportByteLength;
		USHORT OutputReportByteLength;
		USHORT FeatureReportByteLength;
		USHORT Reserved[17];
		USHORT fields_not_used_by_hidapi[10];
	} HIDP_CAPS, *PHIDP_CAPS;
	typedef void* PHIDP_PREPARSED_DATA;
	#define HIDP_STATUS_SUCCESS 0x110000

	typedef BOOLEAN (__stdcall *HidD_GetAttributes_)(HANDLE device, PHIDD_ATTRIBUTES attrib);
	typedef BOOLEAN (__stdcall *HidD_GetSerialNumberString_)(HANDLE device, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_GetManufacturerString_)(HANDLE handle, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_GetProductString_)(HANDLE handle, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_SetFeature_)(HANDLE handle, PVOID data, ULONG length);
	typedef BOOLEAN (__stdcall *HidD_GetFeature_)(HANDLE handle, PVOID data, ULONG length);
	typedef BOOLEAN (__stdcall *HidD_GetInputReport_)(HANDLE handle, PVOID data, ULONG length);
	typedef BOOLEAN (__stdcall *HidD_GetIndexedString_)(HANDLE handle, ULONG string_index, PVOID buffer, ULONG buffer_len);
	typedef BOOLEAN (__stdcall *HidD_GetPreparsedData_)(HANDLE handle, PHIDP_PREPARSED_DATA *preparsed_data);
	typedef BOOLEAN (__stdcall *HidD_FreePreparsedData_)(PHIDP_PREPARSED_DATA preparsed_data);
	typedef NTSTATUS (__stdcall *HidP_GetCaps_)(PHIDP_PREPARSED_DATA preparsed_data, HIDP_CAPS *caps);
	typedef BOOLEAN (__stdcall *HidD_SetNumInputBuffers_)(HANDLE handle, ULONG number_buffers);

	static HidD_GetAttributes_ HidD_GetAttributes;
	static HidD_GetSerialNumberString_ HidD_GetSerialNumberString;
	static HidD_GetManufacturerString_ HidD_GetManufacturerString;
	static HidD_GetProductString_ HidD_GetProductString;
	static HidD_SetFeature_ HidD_SetFeature;
	static HidD_GetFeature_ HidD_GetFeature;
	static HidD_GetInputReport_ HidD_GetInputReport;
	static HidD_GetIndexedString_ HidD_GetIndexedString;
	static HidD_GetPreparsedData_ HidD_GetPreparsedData;
	static HidD_FreePreparsedData_ HidD_FreePreparsedData;
	static HidP_GetCaps_ HidP_GetCaps;
	static HidD_SetNumInputBuffers_ HidD_SetNumInputBuffers;

	// Ro initialization flags; passed to Windows::Runtime::Initialize
	typedef enum RO_INIT_TYPE
	{
#pragma region Desktop Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
		RO_INIT_SINGLETHREADED = 0,      // Single-threaded application
#endif // WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
		RO_INIT_MULTITHREADED = 1,      // COM calls objects on any thread.
	} RO_INIT_TYPE;

	typedef HRESULT(WINAPI* WindowsCreateStringReference_t)(PCWSTR sourceString, UINT32 length, HSTRING_HEADER* hstringHeader, HSTRING* string);
	typedef HRESULT(WINAPI* WindowsDeleteString_t)(HSTRING string);
	typedef PCWSTR(WINAPI* WindowsGetStringRawBuffer_t)(HSTRING string, UINT32* length);
	typedef HRESULT(WINAPI* RoGetActivationFactory_t)(HSTRING activatableClassId, REFIID iid, void** factory);
	typedef HRESULT(WINAPI* RoInitialize_t)(RO_INIT_TYPE initType);
	typedef HRESULT(WINAPI* RoActivateInstance_t)(HSTRING activatableClassId, IInspectable** instance);

	static WindowsCreateStringReference_t WindowsCreateStringReferenceFunc;
	static WindowsGetStringRawBuffer_t WindowsGetStringRawBufferFunc;
	static RoGetActivationFactory_t RoGetActivationFactoryFunc;
	static RoInitialize_t RoInitializeFunc;
	static RoActivateInstance_t RoActivateInstanceFunc;

	static const IID IID___x_ABI_CWindows_CDevices_CEnumeration_CIDeviceInformationStatics = { 0xC17F100E, 0x3A46, 0x4A78, { 0x80, 0x13, 0x76, 0x9D, 0xC9, 0xB9, 0x73, 0x90 } };
	static __x_ABI_CWindows_CDevices_CEnumeration_CIDeviceInformationStatics* WindowsDevicesEnumerationDeviceInformationStatics;
	static const IID IID___x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidDeviceStatics = { 0x9E5981E4, 0x9856, 0x418C, { 0x9F, 0x73, 0x77, 0xDE, 0x0C, 0xD8, 0x57, 0x54 } };
	static __x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidDeviceStatics* WindowsDevicesHumanInterfaceDeviceHidDeviceStatics;
	static const IID IID___x_ABI_CWindows_CStorage_CStreams_CIDataReaderStatics = { 0x11FCBFC8, 0xF93A, 0x471B, { 0xB1, 0x21, 0xF3, 0x79, 0xE3, 0x49, 0x31, 0x3C } };
	static __x_ABI_CWindows_CStorage_CStreams_CIDataReaderStatics* WindowsStorageStreamsIDataReaderStatics;

	static HMODULE lib_handle = NULL;
	static HMODULE lib_handle1 = NULL;
	static BOOLEAN initialized = FALSE;
#endif /* HIDAPI_USE_DDK */

struct hid_device_ {
	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidDevice* device_handle;
	struct hid_device_info dev_info;
	BOOL blocking;
	USHORT output_report_length;
	size_t input_report_length;
	void* last_error_str;
	DWORD last_error_num;
	BOOL read_pending;
	size_t read_len;
	char* read_buf;
	HANDLE read_event;
	void* received_event_handle;
	EventRegistrationToken read_event_token;
	OVERLAPPED ol;
	OVERLAPPED write_ol;
};

static hid_device *new_hid_device()
{
	hid_device* dev = (hid_device*)calloc(1, sizeof(hid_device));
	dev->device_handle = NULL;
	memset(&dev->dev_info, 0, sizeof(struct hid_device_info));
	dev->blocking = TRUE;
	dev->output_report_length = 0;
	dev->input_report_length = 0;
	dev->last_error_str = NULL;
	dev->last_error_num = 0;
	dev->read_pending = FALSE;
	dev->read_buf = NULL;
	dev->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	dev->read_event_token.value = 0;

	return dev;
}

static void free_hid_device(hid_device *dev)
{
	CloseHandle(dev->read_event);
	dev->device_handle->lpVtbl->Release(dev->device_handle);
	LocalFree(dev->last_error_str);
	free(dev->read_buf);
	free(dev);
}

static void register_error(hid_device *dev, const char *op)
{
	WCHAR *ptr, *msg;
	(void)op; // unreferenced  param
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&msg, 0/*sz*/,
		NULL);
	
	/* Get rid of the CR and LF that FormatMessage() sticks at the
	   end of the message. Thanks Microsoft! */
	ptr = msg;
	while (*ptr) {
		if (*ptr == '\r') {
			*ptr = 0x0000;
			break;
		}
		ptr++;
	}

	/* Store the message off in the Device entry so that
	   the hid_error() function can pick it up. */
	LocalFree(dev->last_error_str);
	dev->last_error_str = msg;
}

#ifndef HIDAPI_USE_DDK
static int lookup_functions()
{
	lib_handle = LoadLibraryA("hid.dll");
	lib_handle1 = LoadLibraryA("combase.dll");
	if (lib_handle && lib_handle1) {
#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#define RESOLVE(x) x = (x##_)GetProcAddress(lib_handle, #x); if (!x) return -1;
		RESOLVE(HidD_GetAttributes);
		RESOLVE(HidD_GetSerialNumberString);
		RESOLVE(HidD_GetManufacturerString);
		RESOLVE(HidD_GetProductString);
		RESOLVE(HidD_SetFeature);
		RESOLVE(HidD_GetFeature);
		RESOLVE(HidD_GetInputReport);
		RESOLVE(HidD_GetIndexedString);
		RESOLVE(HidD_GetPreparsedData);
		RESOLVE(HidD_FreePreparsedData);
		RESOLVE(HidP_GetCaps);
		RESOLVE(HidD_SetNumInputBuffers);
#undef RESOLVE
#define RESOLVE(x) x##Func = (x##_t)GetProcAddress(lib_handle1, #x); if (!x##Func) return -1;
		RESOLVE(WindowsCreateStringReference);
		RESOLVE(WindowsGetStringRawBuffer);
		RESOLVE(RoGetActivationFactory);
		RESOLVE(RoInitialize);
		RESOLVE(RoActivateInstance);
		if (WindowsCreateStringReferenceFunc && RoGetActivationFactoryFunc && RoInitializeFunc) {
			RoInitializeFunc(RO_INIT_MULTITHREADED);

			HRESULT hr;
			PCWSTR namespace;
			HSTRING_HEADER namespace_string_header;
			HSTRING namespace_string;

			namespace = L"Windows.Devices.Enumeration.DeviceInformation";
			hr = WindowsCreateStringReferenceFunc(namespace, (UINT32)wcslen(namespace), &namespace_string_header, &namespace_string);
			if (SUCCEEDED(hr)) {
				hr = RoGetActivationFactoryFunc(namespace_string, &IID___x_ABI_CWindows_CDevices_CEnumeration_CIDeviceInformationStatics, &WindowsDevicesEnumerationDeviceInformationStatics);
				if (!SUCCEEDED(hr)) {
					printf("Couldn't find Windows.Devices.Enumeration.DeviceInformation: 0x%x\n", hr);
				}
			}
			namespace = L"Windows.Devices.HumanInterfaceDevice.HidDevice";
			hr = WindowsCreateStringReferenceFunc(namespace, (UINT32)wcslen(namespace), &namespace_string_header, &namespace_string);
			if (SUCCEEDED(hr)) {
				hr = RoGetActivationFactoryFunc(namespace_string, &IID___x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidDeviceStatics, &WindowsDevicesHumanInterfaceDeviceHidDeviceStatics);
				if (!SUCCEEDED(hr)) {
					printf("Couldn't find Windows.Devices.HumanInterfaceDevice.HidDevice: 0x%x\n", hr);
				}
			}
			namespace = L"Windows.Storage.Streams.DataReader";
			hr = WindowsCreateStringReferenceFunc(namespace, (UINT32)wcslen(namespace), &namespace_string_header, &namespace_string);
			if (SUCCEEDED(hr)) {
				hr = RoGetActivationFactoryFunc(namespace_string, &IID___x_ABI_CWindows_CStorage_CStreams_CIDataReaderStatics, &WindowsStorageStreamsIDataReaderStatics);
				if (!SUCCEEDED(hr)) {
					printf("Couldn't find Windows.Storage.Streams.DataReader: 0x%x\n", hr);
				}
			}
		}
#undef RESOLVE
#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif
}
	else
		return -1;

	return 0;
}
#endif

static __x_ABI_CWindows_CStorage_CStreams_CIDataWriter* create_datawriter()
{
	__x_ABI_CWindows_CStorage_CStreams_CIDataWriter* ptr;
	HRESULT hr;
	HSTRING_HEADER namespace_string_header;
	HSTRING namespace_string;
	PCWSTR namespace = L"Windows.Storage.Streams.DataWriter";
	hr = WindowsCreateStringReferenceFunc(namespace, (UINT32)wcslen(namespace), &namespace_string_header, &namespace_string);
	if (SUCCEEDED(hr)) {
		hr = RoActivateInstanceFunc(namespace_string, &ptr);
		if (SUCCEEDED(hr)) {
			return ptr;
		}
		printf("Couldn't find Windows.Storage.Streams.DataWriter: 0x%x\n", hr);
	}
	return NULL;
}

static const IID IIDAsyncOperationCompletedHandlerDeviceInformationCollection = { 0x4a458732, 0x527e, 0x5c73, { 0x9a, 0x68, 0xa7, 0x3d, 0xa3, 0x70, 0xf7, 0x82 } };
static const IID IIDAsyncOperationCompletedHandlerHidDevice = { 0xb0e8e149, 0x0cb6, 0x55a7, { 0xbc, 0xc1, 0xd9, 0x96, 0x32, 0x4d, 0x65, 0xc4 } };
static const IID IIDAsyncOperationCompletedHandlerUint32 = { 0x9343b6e7, 0xe3d2, 0x5e4a, { 0xab, 0x2d, 0x2b, 0xce, 0x49, 0x19, 0xa6, 0xa4 } };
static const IID IIDAsyncOperationCompletedHandlerHidFeatureReport = { 0xdb643555, 0x3d16, 0x57fe, { 0xb7, 0xef, 0x2b, 0xdb, 0xd7, 0x19, 0xfd, 0xbf } };

typedef struct
{
	BEGIN_INTERFACE
		HRESULT(STDMETHODCALLTYPE* QueryInterface)(void* This, REFIID riid, void** ppvObject);
	ULONG(STDMETHODCALLTYPE* AddRef)(void* This);
	ULONG(STDMETHODCALLTYPE* Release)(void* This);
	HRESULT(STDMETHODCALLTYPE* Invoke)(void* This, void* asyncInfo, AsyncStatus asyncStatus);
	END_INTERFACE
} AsyncOperationCompletedHandlerVtbl;

typedef struct
{
	CONST_VTBL AsyncOperationCompletedHandlerVtbl* lpVtbl;
} AsyncOperationCompletedHandlerHandler;

typedef struct
{
	AsyncOperationCompletedHandlerHandler handler;
	IID async_iid;
	HANDLE event;
} AsyncOperationCompletedHandler;

static HRESULT STDMETHODCALLTYPE async_complete_handle_query_interface(void* This, REFIID riid, void** ppvObject)
{
	AsyncOperationCompletedHandler* handle = (AsyncOperationCompletedHandler*)This;
	if (!ppvObject) {
		return E_INVALIDARG;
	}

	*ppvObject = NULL;
	if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &handle->async_iid)) {
		*ppvObject = This;
		return S_OK;
	}
	return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE async_complete_handle_add_ref(void* This)
{
	return 1;
}

static ULONG STDMETHODCALLTYPE async_complete_handle_release(void* This)
{
	return 1;
}

static HRESULT STDMETHODCALLTYPE async_complete_handle_invoke(void* This,
	void* asyncInfo,
	AsyncStatus asyncStatus)
{
	AsyncOperationCompletedHandler* handle = (AsyncOperationCompletedHandler*)This;
	SetEvent(handle->event);
	return S_OK;
}

static AsyncOperationCompletedHandler* create_complete_handle(const IID* iid)
{
	AsyncOperationCompletedHandler* ptr;
	ptr = (AsyncOperationCompletedHandler*)calloc(1, sizeof(AsyncOperationCompletedHandler));
	if (ptr)
	{
		ptr->event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (ptr->event)
		{
			ptr->handler.lpVtbl = (AsyncOperationCompletedHandlerVtbl*)calloc(1, sizeof(AsyncOperationCompletedHandlerVtbl));
			if (ptr->handler.lpVtbl)
			{
				ptr->handler.lpVtbl->QueryInterface = async_complete_handle_query_interface;
				ptr->handler.lpVtbl->AddRef = async_complete_handle_add_ref;
				ptr->handler.lpVtbl->Release = async_complete_handle_release;
				ptr->handler.lpVtbl->Invoke = async_complete_handle_invoke;
				ptr->async_iid = *iid;
				return ptr;
			}
			else
			{
				CloseHandle(ptr->event);
				free(ptr);
			}
		}
		else
		{
			free(ptr);
		}
	}
	return NULL;
}

static void destroy_complete_handle(AsyncOperationCompletedHandler* ptr)
{
	free(ptr->handler.lpVtbl);
	CloseHandle(ptr->event);
	free(ptr);
}

typedef struct
{
	__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgs handler;
	hid_device* dev;
} EventHandlerHIDInputReportReceived;

static HRESULT STDMETHODCALLTYPE event_handler_hid_report_received_query_interface(__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgs* This,
	REFIID riid,
	void** ppvObject)
{
	if (!ppvObject) {
		return E_INVALIDARG;
	}

	*ppvObject = NULL;
	static const IID async_iid = { 0x31e757c8, 0x8f6a, 0x540b, { 0x93, 0x8b, 0xab, 0xa7, 0x9b, 0x6f, 0x03, 0xec } };
	if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &async_iid)) {
		*ppvObject = This;
		return S_OK;
	}
	return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE event_handler_hid_report_received_add_ref(__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgs* This)
{
	return 1;
}

static ULONG STDMETHODCALLTYPE event_handler_hid_report_received_release(__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgs* This)
{
	return 1;
}

static HRESULT STDMETHODCALLTYPE event_handler_hid_report_received_invoke(__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgs* This,
	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidDevice* sender,
	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReportReceivedEventArgs* args)
{
	EventHandlerHIDInputReportReceived* handle = (EventHandlerHIDInputReportReceived*)This;
	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidInputReport* input_report;
	__x_ABI_CWindows_CStorage_CStreams_CIBuffer* buffer;
	UINT32 buffer_len;
	__x_ABI_CWindows_CStorage_CStreams_CIDataReader* data_reader;
	args->lpVtbl->get_Report(args, &input_report);
	input_report->lpVtbl->get_Data(input_report, &buffer);
	WindowsStorageStreamsIDataReaderStatics->lpVtbl->FromBuffer(WindowsStorageStreamsIDataReaderStatics, buffer, &data_reader);
	buffer->lpVtbl->get_Length(buffer, &buffer_len);
	data_reader->lpVtbl->ReadBytes(data_reader, MIN(handle->dev->input_report_length, buffer_len), handle->dev->read_buf);

	data_reader->lpVtbl->Release(data_reader);
	buffer->lpVtbl->Release(buffer);
	input_report->lpVtbl->Release(input_report);

	handle->dev->read_pending = FALSE;
	SetEvent(handle->dev->read_event);
	return S_OK;
}

static EventHandlerHIDInputReportReceived* create_event_handler_hid_report_received(hid_device* dev)
{
	EventHandlerHIDInputReportReceived* ptr;
	ptr = (EventHandlerHIDInputReportReceived*)calloc(1, sizeof(EventHandlerHIDInputReportReceived));
	if (ptr)
	{
		ptr->handler.lpVtbl = (__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgsVtbl*)calloc(1, sizeof(__FITypedEventHandler_2_Windows__CDevices__CHumanInterfaceDevice__CHidDevice_Windows__CDevices__CHumanInterfaceDevice__CHidInputReportReceivedEventArgsVtbl));
		if (ptr->handler.lpVtbl)
		{
			ptr->handler.lpVtbl->QueryInterface = event_handler_hid_report_received_query_interface;
			ptr->handler.lpVtbl->AddRef = event_handler_hid_report_received_add_ref;
			ptr->handler.lpVtbl->Release = event_handler_hid_report_received_release;
			ptr->handler.lpVtbl->Invoke = event_handler_hid_report_received_invoke;
			ptr->dev = dev;
			return ptr;
		}
		else
		{
			free(ptr);
		}
	}
	return NULL;
}

static void destroy_event_handler_hid_report_received(EventHandlerHIDInputReportReceived* ptr)
{
	free(ptr->handler.lpVtbl);
	free(ptr);
}

static HANDLE open_device(const char *path, BOOL open_rw)
{
	HANDLE handle;
	DWORD desired_access = (open_rw)? (GENERIC_WRITE | GENERIC_READ): 0;
	DWORD share_mode = FILE_SHARE_READ|FILE_SHARE_WRITE;

	handle = CreateFileA(path,
		desired_access,
		share_mode,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,/*FILE_ATTRIBUTE_NORMAL,*/
		0);

	return handle;
}

HID_API_EXPORT const struct hid_api_version* HID_API_CALL hid_version()
{
	return &api_version;
}

HID_API_EXPORT const char* HID_API_CALL hid_version_str()
{
	return HID_API_VERSION_STR;
}

int HID_API_EXPORT hid_init(void)
{
#ifndef HIDAPI_USE_DDK
	if (!initialized) {
		if (lookup_functions() < 0) {
			hid_exit();
			return -1;
		}
		initialized = TRUE;
	}
#endif
	return 0;
}

int HID_API_EXPORT hid_exit(void)
{
#ifndef HIDAPI_USE_DDK
	if (lib_handle)
		FreeLibrary(lib_handle);
	if (lib_handle1)
		FreeLibrary(lib_handle1);
	lib_handle = NULL;
	lib_handle1 = NULL;
	initialized = FALSE;
#endif
	return 0;
}

struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
	BOOL res;
	struct hid_device_info* root = NULL; /* return object */
	struct hid_device_info* cur_dev = NULL;
	HRESULT hr;
	PCWSTR wstring;
	const size_t wstr_len = 512;
	WCHAR wstr[512];
	HSTRING_HEADER hstring_header;
	HSTRING hstring;

	if (vendor_id || product_id)
		swprintf_s(wstr, 512, L"System.Devices.InterfaceClassGuid:=\"{4D1E55B2-F16F-11CF-88CB-001111000030}\" AND System.DeviceInterface.Hid.VendorId: = %d AND System.DeviceInterface.Hid.ProductId : = %d", vendor_id, product_id);
	else
		swprintf_s(wstr, 512, L"System.Devices.InterfaceClassGuid:=\"{4D1E55B2-F16F-11CF-88CB-001111000030}\"");
	hr = WindowsCreateStringReferenceFunc(wstr, (UINT32)wcslen(wstr), &hstring_header, &hstring);
	if (!SUCCEEDED(hr)) {
		return NULL;
	}
	/* Get information for all the devices belonging to the HID class. */
	__FIAsyncOperation_1_Windows__CDevices__CEnumeration__CDeviceInformationCollection* async_dev_collection;
	__FIVectorView_1_Windows__CDevices__CEnumeration__CDeviceInformation* dev_collection;
	hr = WindowsDevicesEnumerationDeviceInformationStatics->lpVtbl->FindAllAsyncAqsFilter(WindowsDevicesEnumerationDeviceInformationStatics, hstring, &async_dev_collection);
	if (!SUCCEEDED(hr)) {
		return NULL;
	}
	AsyncOperationCompletedHandler* async_dev_collection_complete_handle = create_complete_handle(&IIDAsyncOperationCompletedHandlerDeviceInformationCollection);
	hr = async_dev_collection->lpVtbl->put_Completed(async_dev_collection, async_dev_collection_complete_handle);
	WaitForSingleObject(async_dev_collection_complete_handle->event, INFINITE);
	do
	{
		hr = async_dev_collection->lpVtbl->GetResults(async_dev_collection, &dev_collection);
	} while (!SUCCEEDED(hr));
	destroy_complete_handle(async_dev_collection_complete_handle);
	async_dev_collection->lpVtbl->Release(async_dev_collection);
	/* Iterate over each device in the HID class */
	UINT32 dev_collection_size;
	dev_collection->lpVtbl->get_Size(dev_collection, &dev_collection_size);
	for (UINT32 i = 0; i < dev_collection_size; ++i) {
		__x_ABI_CWindows_CDevices_CEnumeration_CIDeviceInformation* dev_info;
		hr = dev_collection->lpVtbl->GetAt(dev_collection, i, &dev_info);
		if (!SUCCEEDED(hr)) {
			continue;
		}
		/* Open a handle to the device using win32 api */
		HSTRING dev_path_h;
		PCWSTR dev_path_w;
		char dev_path[512];
		UINT32 convert_ret;
		dev_info->lpVtbl->get_Id(dev_info, &dev_path_h);
		dev_path_w = WindowsGetStringRawBufferFunc(dev_path_h, NULL);
		wcsrtombs_s(&convert_ret, dev_path, 512, &dev_path_w, 512, NULL);
		HANDLE hid_handle = open_device(dev_path, FALSE);
		if (hid_handle == INVALID_HANDLE_VALUE) {
			CloseHandle(hid_handle);
			continue;
		}
		struct hid_device_info* tmp;

		/* VID/PID match. Create the record. */
		tmp = (struct hid_device_info*)calloc(1, sizeof(struct hid_device_info));
		if (cur_dev) {
			cur_dev->next = tmp;
		}
		else {
			root = tmp;
		}
		cur_dev = tmp;

		/* Serial Number */
		wstr[0] = 0x0000;
		res = HidD_GetSerialNumberString(hid_handle, wstr, wstr_len);
		wstr[wstr_len - 1] = 0x0000;
		if (res) {
			cur_dev->serial_number = _wcsdup(wstr);
		}

		/* Manufacturer String */
		wstr[0] = 0x0000;
		res = HidD_GetManufacturerString(hid_handle, wstr, wstr_len);
		wstr[wstr_len - 1] = 0x0000;
		if (res) {
			cur_dev->manufacturer_string = _wcsdup(wstr);
		}

		/* Product String */
		wstr[0] = 0x0000;
		res = HidD_GetProductString(hid_handle, wstr, wstr_len);
		wstr[wstr_len - 1] = 0x0000;
		if (res) {
			cur_dev->product_string = _wcsdup(wstr);
		}
		CloseHandle(hid_handle);

		/* Open a hid device to the device using winrt api*/
		__FIAsyncOperation_1_Windows__CDevices__CHumanInterfaceDevice__CHidDevice* async_hid_dev;
		__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidDevice* hid_dev;
		WindowsDevicesHumanInterfaceDeviceHidDeviceStatics->lpVtbl->FromIdAsync(WindowsDevicesHumanInterfaceDeviceHidDeviceStatics, dev_path_h, FileAccessMode_Read, &async_hid_dev);
		AsyncOperationCompletedHandler* async_hid_complete_handle = create_complete_handle(&IIDAsyncOperationCompletedHandlerHidDevice);
		hr = async_hid_dev->lpVtbl->put_Completed(async_hid_dev, async_hid_complete_handle);
		WaitForSingleObject(async_hid_complete_handle->event, INFINITE);
		do
		{
			hr = async_hid_dev->lpVtbl->GetResults(async_hid_dev, &hid_dev);
		} while (!SUCCEEDED(hr));
		destroy_complete_handle(async_hid_complete_handle);
		async_hid_dev->lpVtbl->Release(async_hid_dev);
		if (hid_dev == NULL)
		{
			if (root == tmp)
			{
				free(tmp);
				cur_dev = NULL;
				root = NULL;
			}
			else
			{
				cur_dev = root;
				while (cur_dev->next && cur_dev->next != tmp)
				{
					cur_dev = cur_dev->next;
				}
				free(tmp);
				cur_dev->next = NULL;
			}
			continue;
		}

		/* Get the Usage Page and Usage for this device. */
		hid_dev->lpVtbl->get_UsagePage(hid_dev, &cur_dev->usage_page);
		hid_dev->lpVtbl->get_UsageId(hid_dev, &cur_dev->usage);

		/* Get the device path */
		cur_dev->path = (char*)calloc(strlen(dev_path) + 1, sizeof(char));
		if (cur_dev->path == NULL)
		{
			continue;   //TODO: should give some warning?
		}
		strncpy_s(cur_dev->path, strlen(dev_path) + 1, dev_path, strlen(dev_path) + 1);
		cur_dev->path[strlen(dev_path)] = '\0';

		/* Product String */
		if (cur_dev->product_string == NULL || strcmp(cur_dev->product_string, "") == 0)
		{
			HSTRING product_h;
			PCWSTR product_w;
			dev_info->lpVtbl->get_Name(dev_info, &product_h);
			product_w = WindowsGetStringRawBufferFunc(product_h, NULL);
			cur_dev->product_string = _wcsdup(product_w);
		}

		/* VID/PID */
		hid_dev->lpVtbl->get_VendorId(hid_dev, &cur_dev->vendor_id);
		hid_dev->lpVtbl->get_ProductId(hid_dev, &cur_dev->product_id);

		/* Release Number */
		hid_dev->lpVtbl->get_Version(hid_dev, &cur_dev->release_number);

		/* Interface Number. It can sometimes be parsed out of the path
		   on Windows if a device has multiple interfaces. See
		   http://msdn.microsoft.com/en-us/windows/hardware/gg487473 or
		   search for "Hardware IDs for HID Devices" at MSDN. If it's not
		   in the path, it's set to -1. */
		char* interface_component = strstr(cur_dev->path, "&MI_");
		if (interface_component) {
			char* hex_str = interface_component + 4;
			char* endptr = NULL;
			cur_dev->interface_number = strtol(hex_str, &endptr, 16);
			if (endptr == hex_str) {
				/* The parsing failed. Set interface_number to -1. */
				cur_dev->interface_number = -1;
			}
		}
		hid_dev->lpVtbl->Release(hid_dev);
	}
	dev_collection->lpVtbl->Release(dev_collection);

	return root;

}

void  HID_API_EXPORT HID_API_CALL hid_free_enumeration(struct hid_device_info *devs)
{
	/* TODO: Merge this with the Linux version. This function is platform-independent. */
	struct hid_device_info *d = devs;
	while (d) {
		struct hid_device_info *next = d->next;
		free(d->path);
		free(d->serial_number);
		free(d->manufacturer_string);
		free(d->product_string);
		free(d);
		d = next;
	}
}


HID_API_EXPORT hid_device * HID_API_CALL hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number)
{
	/* TODO: Merge this functions with the Linux version. This function should be platform independent. */
	struct hid_device_info *devs, *cur_dev;
	const char *path_to_open = NULL;
	hid_device *handle = NULL;
	
	devs = hid_enumerate(vendor_id, product_id);
	cur_dev = devs;
	while (cur_dev) {
		if (cur_dev->vendor_id == vendor_id &&
		    cur_dev->product_id == product_id) {
			if (serial_number) {
				if (cur_dev->serial_number && wcscmp(serial_number, cur_dev->serial_number) == 0) {
					path_to_open = cur_dev->path;
					break;
				}
			}
			else {
				path_to_open = cur_dev->path;
				break;
			}
		}
		cur_dev = cur_dev->next;
	}

	if (path_to_open) {
		/* Open the device */
		handle = hid_open_path(path_to_open);
		if (handle)
		{
			memcpy(&handle->dev_info, cur_dev, sizeof(struct hid_device_info));
		}
	}

	hid_free_enumeration(devs);
	
	return handle;
}

HID_API_EXPORT hid_device * HID_API_CALL hid_open_path(const char *path)
{
	hid_device* dev;
	HIDP_CAPS caps;
	PHIDP_PREPARSED_DATA pp_data = NULL;
	BOOLEAN res;
	NTSTATUS nt_res;
	HRESULT hr;
	HSTRING_HEADER hstring_header;
	HSTRING hstring;
	WCHAR wstr[512];

	if (hid_init() < 0) {
		return NULL;
	}
	dev = new_hid_device();

	/* Open a handle to the device */
	mbstate_t convert_ret;
	mbsrtowcs_s(NULL, wstr, 512, &path, 512, &convert_ret);
	hr = WindowsCreateStringReferenceFunc(wstr, (UINT32)wcslen(wstr), &hstring_header, &hstring);
	__FIAsyncOperation_1_Windows__CDevices__CHumanInterfaceDevice__CHidDevice* async_hid_dev;
	WindowsDevicesHumanInterfaceDeviceHidDeviceStatics->lpVtbl->FromIdAsync(WindowsDevicesHumanInterfaceDeviceHidDeviceStatics, hstring, FileAccessMode_ReadWrite, &async_hid_dev);
	AsyncOperationCompletedHandler* async_hid_complete_handle = create_complete_handle(&IIDAsyncOperationCompletedHandlerHidDevice);
	hr = async_hid_dev->lpVtbl->put_Completed(async_hid_dev, async_hid_complete_handle);
	WaitForSingleObject(async_hid_complete_handle->event, INFINITE);
	do
	{
		hr = async_hid_dev->lpVtbl->GetResults(async_hid_dev, &dev->device_handle);
	} while (!SUCCEEDED(hr));
	destroy_complete_handle(async_hid_complete_handle);

	/* Check validity of write_handle. */
	if (dev->device_handle == NULL)
	{
		WindowsDevicesHumanInterfaceDeviceHidDeviceStatics->lpVtbl->FromIdAsync(WindowsDevicesHumanInterfaceDeviceHidDeviceStatics, hstring, FileAccessMode_Read, &async_hid_dev);
		AsyncOperationCompletedHandler* async_hid_complete_handle = create_complete_handle(&IIDAsyncOperationCompletedHandlerHidDevice);
		hr = async_hid_dev->lpVtbl->put_Completed(async_hid_dev, async_hid_complete_handle);
		WaitForSingleObject(async_hid_complete_handle->event, INFINITE);
		do
		{
			hr = async_hid_dev->lpVtbl->GetResults(async_hid_dev, &dev->device_handle);
		} while (!SUCCEEDED(hr));
		destroy_complete_handle(async_hid_complete_handle);
		/* Check the validity of the limited device_handle. */
		if (dev->device_handle == NULL) {
			/* Unable to open the device, even without read-write mode. */
			register_error(dev, "CreateFile");
			goto err;
		}
	}

	/* Get the Input Report length for the device. */
	UINT16 usage_page, usage_id;
	dev->device_handle->lpVtbl->get_UsagePage(dev->device_handle, &usage_page);
	dev->device_handle->lpVtbl->get_UsageId(dev->device_handle, &usage_id);
	__FIVectorView_1_Windows__CDevices__CHumanInterfaceDevice__CHidNumericControlDescription* input_report_description, * output_report_description;
	UINT32 input_report_description_size, output_report_description_size;
	dev->device_handle->lpVtbl->GetNumericControlDescriptions(dev->device_handle, HidReportType_Input, usage_page, usage_id, &input_report_description);
	dev->device_handle->lpVtbl->GetNumericControlDescriptions(dev->device_handle, HidReportType_Output, usage_page, usage_id, &output_report_description);
	input_report_description->lpVtbl->get_Size(input_report_description, &input_report_description_size);
	output_report_description->lpVtbl->get_Size(output_report_description, &output_report_description_size);
	if (input_report_description)
	{
		__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription* description;
		input_report_description->lpVtbl->GetAt(input_report_description, 0, &description);
		description->lpVtbl->get_ReportSize(description, &dev->input_report_length);
	}
	if (output_report_description)
	{
		__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidNumericControlDescription* description;
		output_report_description->lpVtbl->GetAt(output_report_description, 0, &description);
		description->lpVtbl->get_ReportSize(description, &dev->output_report_length);
	}

	dev->read_buf = (char*)malloc(dev->input_report_length);
	dev->received_event_handle = create_event_handler_hid_report_received(dev);
	dev->device_handle->lpVtbl->add_InputReportReceived(dev->device_handle, dev->received_event_handle, &dev->read_event_token);

	return dev;

err:
	free_hid_device(dev);
	return NULL;
}

int HID_API_EXPORT HID_API_CALL hid_write(hid_device *dev, const unsigned char *data, size_t length)
{
	HRESULT hr;
	UINT32 function_result = 0;

	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidOutputReport* output_report;
	__x_ABI_CWindows_CStorage_CStreams_CIDataWriter* data_writer;
	__x_ABI_CWindows_CStorage_CStreams_CIBuffer* buffer;
	__FIAsyncOperation_1_UINT32* send_async_operation;
	AsyncOperationCompletedHandler* async_complete_handle;
	hr = dev->device_handle->lpVtbl->CreateOutputReportById(dev->device_handle, data[0], &output_report);
	if (SUCCEEDED(hr) || output_report == NULL)
	{
		/* CreateOutputReport failed. Return error. */
		register_error(dev, "CreateOutputReport");
		return -1;
	}
	data_writer = create_datawriter();
	if (data_writer == NULL)
	{
		output_report->lpVtbl->Release(output_report);
		return -1;
	}
	data_writer->lpVtbl->WriteBytes(data_writer, length, data);
	data_writer->lpVtbl->DetachBuffer(data_writer, &buffer);
	output_report->lpVtbl->put_Data(output_report, buffer);
	dev->device_handle->lpVtbl->SendOutputReportAsync(dev->device_handle, output_report, &send_async_operation);
	async_complete_handle = create_complete_handle(&IIDAsyncOperationCompletedHandlerUint32);
	send_async_operation->lpVtbl->put_Completed(send_async_operation, async_complete_handle);
	if (WaitForSingleObject(async_complete_handle->event, 1000) != WAIT_OBJECT_0) {
		send_async_operation->lpVtbl->Release(send_async_operation);
		destroy_complete_handle(async_complete_handle);
		buffer->lpVtbl->Release(buffer);
		data_writer->lpVtbl->Release(data_writer);
		output_report->lpVtbl->Release(output_report);
		/* There was a Timeout. */
		register_error(dev, "SendOutputReport/WaitForSingleObject Timeout");
		return -1;
	}
	do
	{
		hr = send_async_operation->lpVtbl->GetResults(send_async_operation, &function_result);
	} while (!SUCCEEDED(hr));
	send_async_operation->lpVtbl->Release(send_async_operation);
	destroy_complete_handle(async_complete_handle);
	buffer->lpVtbl->Release(buffer);
	data_writer->lpVtbl->Release(data_writer);
	output_report->lpVtbl->Release(output_report);

	return function_result;
}


int HID_API_EXPORT HID_API_CALL hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds)
{
	BOOL res = FALSE;
	size_t copy_len = 0;
	__FIAsyncOperation_1_Windows__CDevices__CHumanInterfaceDevice__CHidInputReport* input_report;

	if (!dev->read_pending)
	{
		dev->read_pending = TRUE;
		dev->read_len = 0;
		ResetEvent(dev->read_event);
		dev->device_handle->lpVtbl->GetInputReportAsync(dev->device_handle, &input_report);
	}

	if (milliseconds >= 0)
	{
		/* See if there is any data yet. */
		res = WaitForSingleObject(dev->read_event, milliseconds);
		if (res != WAIT_OBJECT_0) {
			/* There was no data this time. Return zero bytes available,
				but leave the Overlapped I/O running. */
			return 0;
		}
	}

	if (dev->read_len > 0)
	{
		if (dev->read_buf[0] == 0x0)
		{
			/* If report numbers aren't being used, but Windows sticks a report
			   number (0x0) on the beginning of the report anyway. To make this
			   work like the other platforms, and to make it work more like the
			   HID spec, we'll skip over this byte. */
			dev->read_len--;
			copy_len = MIN(dev->read_len, length);
			memcpy(data, dev->read_buf + 1, copy_len);
		}
		else {
			/* Copy the whole buffer, report number and all. */
			copy_len = MIN(dev->read_len, length);
			memcpy(data, dev->read_buf, copy_len);
		}
	}

	return copy_len;
}

int HID_API_EXPORT HID_API_CALL hid_read(hid_device *dev, unsigned char *data, size_t length)
{
	return hid_read_timeout(dev, data, length, (dev->blocking)? -1: 0);
}

int HID_API_EXPORT HID_API_CALL hid_set_nonblocking(hid_device *dev, int nonblock)
{
	dev->blocking = !nonblock;
	return 0; /* Success */
}

int HID_API_EXPORT HID_API_CALL hid_send_feature_report(hid_device *dev, const unsigned char *data, size_t length)
{
	HRESULT hr;
	UINT32 send_byte;
	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidFeatureReport* feature_report;
	__x_ABI_CWindows_CStorage_CStreams_CIDataWriter* data_writer;
	__x_ABI_CWindows_CStorage_CStreams_CIBuffer* buffer;
	__FIAsyncOperation_1_UINT32* async_operation;
	AsyncOperationCompletedHandler* async_operation_complete_handler;
	dev->device_handle->lpVtbl->CreateFeatureReportById(dev->device_handle, data[0], &feature_report);
	data_writer = create_datawriter();
	data_writer->lpVtbl->WriteBytes(data_writer, length, data);
	data_writer->lpVtbl->DetachBuffer(data_writer, &buffer);
	feature_report->lpVtbl->put_Data(feature_report, buffer);
	dev->device_handle->lpVtbl->SendFeatureReportAsync(dev->device_handle, feature_report, &async_operation);
	async_operation_complete_handler = create_complete_handle(&IIDAsyncOperationCompletedHandlerUint32);
	async_operation->lpVtbl->put_Completed(async_operation, async_operation_complete_handler);
	WaitForSingleObject(async_operation_complete_handler, INFINITE);
	do
	{
		hr = async_operation->lpVtbl->GetResults(async_operation, &send_byte);
	} while (!SUCCEEDED(hr));
	destroy_complete_handle(async_operation_complete_handler);
	async_operation->lpVtbl->Release(async_operation);
	buffer->lpVtbl->Release(buffer);
	data_writer->lpVtbl->Release(data_writer);
	feature_report->lpVtbl->Release(feature_report);

	return send_byte;
}


int HID_API_EXPORT HID_API_CALL hid_get_feature_report(hid_device *dev, unsigned char *data, size_t length)
{
	HRESULT hr;
	size_t byte_read;
	__FIAsyncOperation_1_Windows__CDevices__CHumanInterfaceDevice__CHidFeatureReport* async_feature_report;
	AsyncOperationCompletedHandler* async_operation_complete_handler;
	__x_ABI_CWindows_CDevices_CHumanInterfaceDevice_CIHidFeatureReport* feature_report;
	__x_ABI_CWindows_CStorage_CStreams_CIBuffer* buffer;
	__x_ABI_CWindows_CStorage_CStreams_CIDataReader* data_reader;

	dev->device_handle->lpVtbl->GetFeatureReportByIdAsync(dev->device_handle, data[0], &async_feature_report);
	async_operation_complete_handler = create_complete_handle(&IIDAsyncOperationCompletedHandlerHidFeatureReport);
	async_feature_report->lpVtbl->put_Completed(async_feature_report, async_operation_complete_handler);
	WaitForSingleObject(async_operation_complete_handler->event, INFINITE);
	do
	{
		hr = async_feature_report->lpVtbl->GetResults(async_feature_report, &feature_report);
	} while (!SUCCEEDED(hr));
	feature_report->lpVtbl->get_Data(feature_report, &buffer);
	WindowsStorageStreamsIDataReaderStatics->lpVtbl->FromBuffer(WindowsStorageStreamsIDataReaderStatics, buffer, &data_reader);
	buffer->lpVtbl->get_Length(buffer, &byte_read);
	byte_read = MIN(byte_read, length);
	data_reader->lpVtbl->ReadBytes(data_reader, byte_read, data);

	data_reader->lpVtbl->Release(data_reader);
	buffer->lpVtbl->Release(buffer);
	feature_report->lpVtbl->Release(feature_report);
	destroy_complete_handle(async_operation_complete_handler);
	async_feature_report->lpVtbl->Release(async_feature_report);

	return byte_read;
}


int HID_API_EXPORT HID_API_CALL hid_get_input_report(hid_device *dev, unsigned char *data, size_t length)
{
	BOOL res;
#if 0
	res = HidD_GetInputReport(dev->device_handle, data, length);
	if (!res) {
		register_error(dev, "HidD_GetInputReport");
		return -1;
	}
	return length;
#else
	DWORD bytes_returned;

	OVERLAPPED ol;
	memset(&ol, 0, sizeof(ol));

	res = DeviceIoControl(dev->device_handle,
		IOCTL_HID_GET_INPUT_REPORT,
		data, (DWORD) length,
		data, (DWORD) length,
		&bytes_returned, &ol);

	if (!res) {
		if (GetLastError() != ERROR_IO_PENDING) {
			/* DeviceIoControl() failed. Return error. */
			register_error(dev, "Send Input Report DeviceIoControl");
			return -1;
		}
	}

	/* Wait here until the write is done. This makes
	   hid_get_feature_report() synchronous. */
	res = GetOverlappedResult(dev->device_handle, &ol, &bytes_returned, TRUE/*wait*/);
	if (!res) {
		/* The operation failed. */
		register_error(dev, "Send Input Report GetOverLappedResult");
		return -1;
	}

	return bytes_returned;
#endif
}

void HID_API_EXPORT HID_API_CALL hid_close(hid_device *dev)
{
	if (!dev)
		return;
	CancelIo(dev->device_handle);
	free_hid_device(dev);
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	BOOL res;

	res = HidD_GetManufacturerString(dev->device_handle, string, sizeof(wchar_t) * (DWORD) MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(dev, "HidD_GetManufacturerString");
		return -1;
	}

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	BOOL res;

	res = HidD_GetProductString(dev->device_handle, string, sizeof(wchar_t) * (DWORD) MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(dev, "HidD_GetProductString");
		return -1;
	}

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	BOOL res;

	res = HidD_GetSerialNumberString(dev->device_handle, string, sizeof(wchar_t) * (DWORD) MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(dev, "HidD_GetSerialNumberString");
		return -1;
	}

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_indexed_string(hid_device *dev, int string_index, wchar_t *string, size_t maxlen)
{
	BOOL res;

	res = HidD_GetIndexedString(dev->device_handle, string_index, string, sizeof(wchar_t) * (DWORD) MIN(maxlen, MAX_STRING_WCHARS));
	if (!res) {
		register_error(dev, "HidD_GetIndexedString");
		return -1;
	}

	return 0;
}


HID_API_EXPORT const wchar_t * HID_API_CALL  hid_error(hid_device *dev)
{
	if (dev) {
		if (dev->last_error_str == NULL)
			return L"Success";
		return (wchar_t*)dev->last_error_str;
	}

	// Global error messages are not (yet) implemented on Windows.
	return L"hid_error for global errors is not implemented yet";
}


/*#define PICPGM*/
/*#define S11*/
#define P32
#ifdef S11 
  unsigned short VendorID = 0xa0a0;
	unsigned short ProductID = 0x0001;
#endif

#ifdef P32
  unsigned short VendorID = 0x04d8;
	unsigned short ProductID = 0x3f;
#endif


#ifdef PICPGM
  unsigned short VendorID = 0x04d8;
  unsigned short ProductID = 0x0033;
#endif


#if 0
int __cdecl main(int argc, char* argv[])
{
	int res;
	unsigned char buf[65];

	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	/* Set up the command buffer. */
	memset(buf,0x00,sizeof(buf));
	buf[0] = 0;
	buf[1] = 0x81;
	

	/* Open the device. */
	int handle = open(VendorID, ProductID, L"12345");
	if (handle < 0)
		printf("unable to open device\n");


	/* Toggle LED (cmd 0x80) */
	buf[1] = 0x80;
	res = write(handle, buf, 65);
	if (res < 0)
		printf("Unable to write()\n");

	/* Request state (cmd 0x81) */
	buf[1] = 0x81;
	write(handle, buf, 65);
	if (res < 0)
		printf("Unable to write() (2)\n");

	/* Read requested state */
	read(handle, buf, 65);
	if (res < 0)
		printf("Unable to read()\n");

	/* Print out the returned buffer. */
	for (int i = 0; i < 4; i++)
		printf("buf[%d]: %d\n", i, buf[i]);

	return 0;
}
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
