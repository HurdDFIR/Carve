import wmi
import ctypes
import os
from carve_log import l

class VSS():
    # TODO: access already made VSS
    def __init__(self, drive_root: str):
        """
        Initialize the vss class with the drive root. 
        Parameters:
            drive_root (str): The root of the drive to be initialized.
            Example: drive_root='C:\\'
        """
        os_windows = self._is_os_supported()
        is_admin = self._is_admin()
        if not os_windows:
            raise BaseExceptionGroup(f"This OS is not supported: {os.name}")
        if not is_admin:
            raise Exception("This operation requires admin. Please run as admin.")
        
        self._wmi_object = wmi.WMI()
        self._drive_root = drive_root
        self._vss_enabled, self._vss_was_stopped = self._enable_vss()
        if self._vss_enabled:
            try:
                self.vss = self.create_shadow()
                self.path = self.vss.DeviceObject
                self.id = self.vss.ID
                self.providerid = self.vss.ProviderID
                self.hostname = self.vss.ServiceMachine
                self.volumename = self.vss.VolumeName

            except Exception as e:
                l.error(f"Failed to create shadow copy: {e}")

    def _disable_vss(self):
        service_name = "VSS"
        vss_service = self._wmi_object.Win32_Service(Name=service_name)[0]
        result = vss_service.ChangeStartMode("Disabled")
        return result

    def _enable_vss(self):
        service_name = "VSS"
        vss_service = self._wmi_object.Win32_Service(Name=service_name)[0]
        if vss_service.State == "Stopped" and vss_service.StartMode == "Disabled":
            result = vss_service.ChangeStartMode("Manual")

            if result[0] != 0:
                raise (f"Failed to enable VSS.")
            
            else:
                return True, True
            
        else:
            return True, False

    def _is_os_supported(self) -> bool:
        """
        Private method for checking if os is supported
        """
        return os.name == "nt"

    def _is_admin(self) -> bool:
        """
        Private method for checking if we're admin
        """
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def create_shadow(self):
        """
        Create a shadow copy using the Win32_ShadowCopy class and return the shadow object.
        """
        result_codes = {
            0: "Success",
            1: "AccessDenied",
            2: "InvalidArgument",
            3: "VolumeNotFound",
            4: "VolumeNotSupported",
            5: "UnsupportedContext",
            6: "InsufficientStorage",
            7: "VolumeInUse",
            8: "TooManyShadowCopies",
            9: "AnotherShadowCopyInProgress",
            10: "ProviderVetoedOperation",
            11: "ProviderNotRegistered",
            12: "ProviderFailure",
            13: "UnknownError"
        }

        result, shadow_id = self._wmi_object.Win32_ShadowCopy.Create(
            Context="ClientAccessible", Volume=f"{self._drive_root}"
        )
        l.debug(f"result: {result} | shadow_id: {shadow_id}")
        if result != 0:
            raise Exception(f"Failed to create shadow copy: {result_codes[result]}")

        shadow_obj = self._wmi_object.Win32_ShadowCopy(ID=shadow_id)[0]

        return shadow_obj

    def delete(self):
        """
        A method to delete a shadow copy, handling any exceptions that occur.
        """
        try:
            self.vss.Delete_()
            if self._vss_was_stopped:
                is_disabled = self._disable_vss()
                if is_disabled:
                    print("VSS service has been returned to a disabled state.")

        except Exception as e:
            print(f"Failed to delete shadow copy: {e}")

