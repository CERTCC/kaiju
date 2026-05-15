package kaiju.tools.ghihorn.api;

import com.google.common.base.Verify;
import ghidra.program.model.listing.Function;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiFunction;

/**
 * This class is to ensure consistent naming throughout the tool
 */
public class ApiEntry {
    private final String libName, apiName;

    private ApiEntry(final String lib, final String api) {
        libName = lib;
        apiName = api;
    }

    public static ApiEntry create(final String lib, final String api) {

        Verify.verify(lib != null && !lib.isEmpty());
        Verify.verify(api != null && !api.isEmpty());

        return new ApiEntry(normalizeName(lib), normalizeName(api));
    }

    public static ApiEntry create(final Function func) {

        Verify.verify(func != null);

        return new ApiEntry(normalizeName(func.getParentNamespace().getName()), normalizeName(func.getName()));
    }

    /**
     * @return the apiName
     */
    public String getApiName() {
        return apiName;
    }

    /**
     * @return the libName
     */
    public String getLibName() {
        return libName;
    }

    public String formatApiName() {
        return new StringBuilder(libName).append(ApiFunction.API_NAME_SEPARATOR).append(apiName).toString().toUpperCase();
    }

    /**
     * Exported DLL names start with '_' and have "@#", strip that off
     * 
     * @param name
     * @return the normalized name
     */
    private static String normalizeName(final String n) {

        int end = n.lastIndexOf('@');
        int start = 0;
        if (n.charAt(0) == '_') {
            start = 1;
        }

        if (end == -1) {
            end = n.length();
        }

        return n.substring(start, end).toUpperCase();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((apiName == null) ? 0 : apiName.hashCode());
        result = prime * result + ((libName == null) ? 0 : libName.hashCode());
        return result;
    }
    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ApiEntry other = (ApiEntry) obj;

        if (apiName == null) {
            if (other.apiName != null)
                return false;
        } else if (!apiName.equals(other.apiName))
            return false;

        if (libName == null) {
            if (other.libName != null)
                return false;
        } else if (!libName.equals(other.libName))
            return false;

        return true;
    }

    @Override
    public String toString() {
        return new StringBuilder(libName).append(ApiFunction.API_NAME_SEPARATOR).append(apiName).toString();
    }
}
