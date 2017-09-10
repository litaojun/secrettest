package com.ucs.secrettest.util;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;


public class StringUtil extends StringUtils
{

    public StringUtil()
    {
    }
    
    /**
     * @param ids
     * @return
     */
    public static String arrayToString(String[] ids)
    {
    	 String needId = "";   
         for(String id : ids){   
             needId += "'" + id + "'" + ",";   
         }   
         return needId = needId.substring(0, needId.length()-1); 	
    }
    
    /**
     * @param str
     * @return
     */
    public static boolean isNotBlank(String str)
    {
    	 boolean result = true;
    	 if(null==str || "".equals(str.trim())){
    		 result = false;
    	 }
    	 return result;
    }
    
    /**
     * @param ids
     * @return
     */
    public static String arrayToString(List<String> ids)
    {
         String needId = "";   
         for(String id : ids){   
             needId += "'" + id + "'" + ",";   
         }   
         return needId = needId.substring(0, needId.length()-1);    
    }
    
    /**
     * 将文件名中的汉字转为UTF8编码的串,以便下载时能正确显示另存的文件名.
     * @param s 原文件名
     * @return 重新编码后的文件名
     */
    public static String toUtf8String(String s)
    {
    	StringBuffer sb = new StringBuffer();
    	for (int i=0;i<s.length();i++)
    	{
    		char c = s.charAt(i);
    		if (c >= 0 && c <= 255)
    		{
    			sb.append(c);
    		} else {
    			byte[] b;
    			try {
    				b = Character.toString(c).getBytes("UTF-8");
    			} catch (Exception ex) {
    				b = new byte[0];
    			}
    			for (int j = 0; j < b.length; j++)
    			{
    				int k = b[j];
    				if (k < 0) k += 256;
    				sb.append("%" + Integer.toHexString(k).toUpperCase());
    			}
    		}
    	}
    	return sb.toString();
    }

    public static final String replace(String line, String oldString, String newString, int count[])
    {
        if(line == null)
            return null;
        int i = 0;
        if((i = line.indexOf(oldString, i)) >= 0)
        {
            int counter = 0;
            counter++;
            char line2[] = line.toCharArray();
            char newString2[] = newString.toCharArray();
            int oLength = oldString.length();
            StringBuffer buf = new StringBuffer(line2.length);
            buf.append(line2, 0, i).append(newString2);
            i += oLength;
            int j;
            for(j = i; (i = line.indexOf(oldString, i)) > 0; j = i)
            {
                counter++;
                buf.append(line2, j, i - j).append(newString2);
                i += oLength;
            }

            buf.append(line2, j, line2.length - j);
            count[0] = counter;
            return buf.toString();
        } else
        {
            return line;
        }
    }

    public static final String escapeHTMLTags(String input)
    {
        if(input == null || input.length() == 0)
            return input;
        StringBuffer buf = new StringBuffer(input.length());
        char ch = ' ';
        for(int i = 0; i < input.length(); i++)
        {
            ch = input.charAt(i);
            if(ch == '<')
                buf.append("&lt;");
            else
            if(ch == '>')
                buf.append("&gt;");
            else
                buf.append(ch);
        }

        return buf.toString();
    }

    public static final synchronized String hash(String data)
    {
        if(digest == null)
            try
            {
                digest = MessageDigest.getInstance("MD5");
            }
            catch(NoSuchAlgorithmException nsae)
            {
                System.err.println("Failed to load the MD5 MessageDigest. Numeta will be unable to function normally.");
                nsae.printStackTrace();
            }
        digest.update(data.getBytes());
        return toHex(digest.digest());
    }

    public static final String toHex(byte hash[])
    {
        StringBuffer buf = new StringBuffer(hash.length * 2);
        for(int i = 0; i < hash.length; i++)
        {
            if((hash[i] & 0xff) < 16)
                buf.append("0");
            buf.append(Long.toString(hash[i] & 0xff, 16));
        }

        return buf.toString();
    }

    public static final String[] toLowerCaseWordArray(String text)
    {
        if(text == null || text.length() == 0)
            return new String[0];
        StringTokenizer tokens = new StringTokenizer(text, " ,\r\n.:/\\+");
        String words[] = new String[tokens.countTokens()];
        for(int i = 0; i < words.length; i++)
            words[i] = tokens.nextToken().toLowerCase();

        return words;
    }

    public static final String[] removeCommonWords(String words[])
    {
        if(commonWordsMap == null)
            synchronized(initLock)
            {
                if(commonWordsMap == null)
                {
                    commonWordsMap = new HashMap<String, String>();
                    for(int i = 0; i < commonWords.length; i++)
                        commonWordsMap.put(commonWords[i], commonWords[i]);

                }
            }
        ArrayList<String> results = new ArrayList<String>(words.length);
        for(int i = 0; i < words.length; i++)
            if(!commonWordsMap.containsKey(words[i]))
                results.add(words[i]);

        return (String[])results.toArray(new String[results.size()]);
    }

    public static String randomString()
    {
        return makeRandom(5);
    }

    public static String randomString(int numCharacters)
    {
        return makeRandom(numCharacters);
    }

    private static String makeRandom(int numChars)
    {
        String s = "";
        char letters[] = initLetters();
        for(int i = 0; i < numChars; i++)
        {
                int d2 = (int)(Math.random() * 100D) % 26;
                s = s + letters[d2];
        }

        return s;
    }

    private static char[] initLetters()
    {
        char ca[] = new char[26];
        for(int i = 0; i < 26; i++)
            ca[i] = (char)(65 + i);

        return ca;
    }

    public static boolean equals(String str1, String str2)
    {
        String s1 = NVL(str1);
        String s2 = NVL(str2);
        return s1.equals(s2);
    }

    public static final String quoteStr(String s)
    {
        if(s == null || s.length() < 1)
            return "";
        char chars[] = s.toCharArray();
        StringBuffer sb = new StringBuffer();
        boolean needQuotes = false;
        for(int i = 0; i < chars.length; i++)
            switch(chars[i])
            {
            case 10: // '\n'
                needQuotes = true;
                sb.append("\\n");
                break;

            case 8: // '\b'
                needQuotes = true;
                sb.append("\\b");
                break;

            case 13: // '\r'
                needQuotes = true;
                sb.append("\\r");
                break;

            case 12: // '\f'
                needQuotes = true;
                sb.append("\\f");
                break;

            case 34: // '"'
                needQuotes = true;
                sb.
append("\\\"");
                break;

            case 92: // '\\'
                needQuotes = true;
                sb.append("\\\\");
                break;

            case 9: // '\t'
            case 32: // ' '
            case 33: // '!'
            case 35: // '#'
            case 36: // '$'
            case 37: // '%'
            case 38: // '&'
            case 39: // '\''
            case 40: // '('
            case 41: // ')'
            case 42: // '*'
            case 43: // '+'
            case 44: // ','
            case 47: // '/'
            case 58: // ':'
            case 59: // ';'
            case 60: // '<'
            case 61: // '='
            case 62: // '>'
            case 63: // '?'
            case 91: // '['
            case 93: // ']'
            case 94: // '^'
            case 96: // '`'
            case 123: // '{'
            case 124: // '|'
            case 125: // '}'
            case 126: // '~'
                needQuotes = true;
                sb.append(chars[i]);
                break;

            case 11: // '\013'
            case 14: // '\016'
            case 15: // '\017'
            case 16: // '\020'
            case 17: // '\021'
            case 18: // '\022'
            case 19: // '\023'
            case 20: // '\024'
            case 21: // '\025'
            case 22: // '\026'
            case 23: // '\027'
            case 24: // '\030'
            case 25: // '\031'
            case 26: // '\032'
            case 27: // '\033'
            case 28: // '\034'
            case 29: // '\035'
            case 30: // '\036'
            case 31: // '\037'
            case 45: // '-'
            case 46: // '.'
            case 48: // '0'
            case 49: // '1'
            case 50: // '2'
            case 51: // '3'
            case 52: // '4'
            case 53: // '5'
            case 54: // '6'
            case 55: // '7'
            case 56: // '8'
            case 57: // '9'
            case 64: // '@'
            case 65: // 'A'
            case 66: // 'B'
            case 67: // 'C'
            case 68: // 'D'
            case 69: // 'E'
            case 70: // 'F'
            case 71: // 'G'
            case 72: // 'H'
            case 73: // 'I'
            case 74: // 'J'
            case 75: // 'K'
            case 76: // 'L'
            case 77: // 'M'
            case 78: // 'N'
            case 79: // 'O'
            case 80: // 'P'
            case 81: // 'Q'
            case 82: // 'R'
            case 83: // 'S'
            case 84: // 'T'
            case 85: // 'U'
            case 86: // 'V'
            case 87: // 'W'
            case 88: // 'X'
            case 89: // 'Y'
            case 90: // 'Z'
            case 95: // '_'
            case 97: // 'a'
            case 98: // 'b'
            case 99: // 'c'
            case 100: // 'd'
            case 101: // 'e'
            case 102: // 'f'
            case 103: // 'g'
            case 104: // 'h'
            case 105: // 'i'
            case 106: // 'j'
            case 107: // 'k'
            case 108: // 'l'
            case 109: // 'm'
            case 110: // 'n'
            case 111: // 'o'
            case 112: // 'p'
            case 113: // 'q'
            case 114: // 'r'
            case 115: // 's'
            case 116: // 't'
            case 117: // 'u'
            case 118: // 'v'
            case 119: // 'w'
            case 120: // 'x'
            case 121: // 'y'
            case 122: // 'z'
            default:
                if(chars[i] < ' ' || chars[i] == '\177')
                {
                    needQuotes = true;
                    int ival = chars[i];
                    sb.append('\\');
                    sb.append(digits[(ival & 0xc0) >> 6]);
                    sb.append(digits[(ival & 0x38) >> 3]);
                    sb.append(digits[ival & 7]);
                    break;
                }
                if(chars[i] > '\177')
                {
                    needQuotes = true;
                    int ival = chars[i];
                    sb.append("\\u");
                    sb.append(digits[(ival & 0xf000) >> 12]);
                    sb.append(digits[(ival & 0xf00) >> 8]);
                    sb.append(digits[(ival & 0xf0) >> 4]);
                    sb.append(digits[ival & 0xf]);
                } else
                {
                    sb.append(chars[i]);
                }
                break;
            }

        if(needQuotes)
            return "\"" 
+ sb.toString() + "\"";
        else
            return sb.toString();
    }

    public boolean containsWhiteSpace(String str)
    {
        if(str.indexOf(" ") != -1)
            return true;
        return str.indexOf("\t") != -1;
    }

    public static String removeQuote(String str)
    {
        if(str == null)
            str = "";
        str.trim();
        int index = str.lastIndexOf("\"");
        if(index == str.length() - 1)
            str = str.substring(0, str.length() - 2);
        index = str.indexOf("\"");
        if(index == 0)
            str = str.substring(1);
        return str;
    }

    public static String NVL(BigDecimal key)
    {
        if(key == null || key.longValue() == 0L)
            return "";
        else
            return key.toString();
    }

    public static String NVL(int integerValue)
    {
        return String.valueOf(integerValue);
    }

    public static String NVL(Double dValue)
    {
        return String.valueOf(dValue);
    }

    public static String NVL(double dValue)
    {
        return String.valueOf(dValue);
    }

    public static String NVL(float fValue)
    {
        return String.valueOf(fValue);
    }

    public static String NVL(boolean booleanValue)
    {
        if(booleanValue)
            return "yes";
        else
            return "no";
    }

    public static final String NVL(String input, String nullVal)
    {
        return input == null ? nullVal : input;
    }

    public static final String NVL(String input)
    {
        if(input == null)
            return "";
        else
            return input.trim();
    }

    public static String trim(String str)
    {
        if(str == null)
            return "";
        else
            return str.trim();
    }

    public static String[] trim(String strs[])
    {
        for(int i = 0; i < strs.length; i++)
            trim(strs[i]);

        return strs;
    }

    public static String CapitalizeInitial(String str)
    {
        if(str == null)
            return "";
        str = str.trim();
        if(str.equals(""))
        {
            return "";
        } else
        {
            str = str.toLowerCase();
            String str1 = Character.toUpperCase(str.charAt(0)) + str.substring(1);
            return str1;
        }
    }

   

    

    public static String removeExtraSpace(String str)
    {
        StringTokenizer token = new StringTokenizer(str, " ");
        StringBuffer ret = new StringBuffer();
        for(; token.hasMoreElements(); ret.append((String)token.nextElement() + " "));
        return trim(ret.toString());
    }


    private static Object initLock = new Object();
    private static MessageDigest digest = null;
    private static final String commonWords[] = {
        "a", "and", "as", "at", "be", "do", "i", "if", "in", "is", 
        "it", "so", "the", "to"
    };
    private static Map<String, String> commonWordsMap = null;
    private static final char digits[] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
        'a', 'b', 'c', 'd', 'e', 'f'
    };
    
    /**
     * 过滤特殊字符
     * @param str
     * @return
     */
    public static String filterSpecialChar(String str) {
        if(str==null||str.length()==0){
            return "";
        }
        String regEx = "[`~!@#$%^&*()+=|{}':;',\\[\\].<>/?！￥（）【】‘；：”“’。，、？]";
        Pattern p = Pattern.compile(regEx);
        Matcher m = p.matcher(str);
        return m.replaceAll("").trim();
    }
    
    /**
     * 截取字符长度
     * @param str
     * @param length
     * @return
     */
    public static String subString(String str,int length){
        if(str==null||str.length()<=length){
            return str;
        }
        return str.substring(0, length);
    }
    
    /**
	 * 字符串截取固定长度（一个中文字长度为2）
	 * 
	 * @param str
	 * @param len
	 * @return
	 */
	public static String getLimitLengthString(String str, int len) {
		try {
			int counterOfDoubleByte = 0;
			byte[] b = str.getBytes("gb2312");
			if (b.length <= len)
				return str;
			for (int i = 0; i < len; i++) {
				if (b[i] < 0)
					counterOfDoubleByte++;
			}
			if (counterOfDoubleByte % 2 == 0)
				return new String(b, 0, len, "gb2312");
			else
				return new String(b, 0, len - 1, "gb2312");
		} catch (Exception ex) {
			return "";
		}
	}
	
	/**
	 * 取数组中的元素,防止数组下标溢出
	 * @param strs
	 * @param i
	 * @return
	 */
	public static String getStrFromArray(String[] strs,int i) {
		if(strs==null || strs.length == 0) {
			return null;
		}
		int length = strs.length;
		if(i<length && i>-1) {
			return strs[i];
		}
		return null;
	}
	
	/**
	 * 判断字符串是不是全是数字
	 * @param str
	 * @return
	 */
	public static boolean isNumeric(String str){ 
		   Pattern pattern = Pattern.compile("[0-9]*"); 
		   Matcher isNum = pattern.matcher(str);
		   if( !isNum.matches() ){
		       return false; 
		   } 
		   return true; 
	}

	public static String decode(String param) {
		if(StringUtil.isBlank(param)) {
			return null;
		}
		String result = null;
		try {
			result = URLDecoder.decode(param,"UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return result;
	}
	
}
