// Ring0 PE Encryptor Driver - Generation ID: 399124
#include <ntddk.h>
#include <wdf.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;
    PDEVICE_OBJECT deviceObject = NULL;
    
    RtlInitUnicodeString(&deviceName, L"\\Device\\dev52363");
    RtlInitUnicodeString(&symbolicName, L"\\??\\dev52363");
    
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                     FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    
    if (!NT_SUCCESS(status)) return status;
    
    status = IoCreateSymbolicLink(&symbolicName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    DriverObject->MajorFunction[IRP_MJ_CREATE] = drv71775Create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = drv71775Close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = drv71775DeviceControl;
    DriverObject->DriverUnload = drv71775Unload;
    
    deviceObject->Flags |= DO_DIRECT_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    return STATUS_SUCCESS;
}

VOID encrypt18200(PUCHAR data, SIZE_T size, UCHAR key) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= key;
        data[i] = _rotl8(data[i], 5);
        data[i] += 0x69;
    }
}

NTSTATUS drv71775DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    
    switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
        case CTL_CODE(FILE_DEVICE_UNKNOWN, 0xfc2, METHOD_BUFFERED, FILE_ANY_ACCESS): {
            // Ring0 PE encryption request
            PUCHAR buffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            SIZE_T size = irpStack->Parameters.DeviceIoControl.InputBufferLength;
            
            if (buffer && size > 0) {
                encrypt18200(buffer, size, 0x30);
                bytesReturned = size;
            }
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

