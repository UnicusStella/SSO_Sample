package com.dreamsecurity.sso.server.util;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import com.dreamsecurity.sso.lib.jsn.JSONArray;
import com.dreamsecurity.sso.lib.jsn.JSONObject;

public class JsonUtil
{
	public String ajaxPaser(List<Object> value)
	{
		JSONObject cel = new JSONObject();
		Object clas = value.get(0);
		Field[] fields = clas.getClass().getDeclaredFields();
		for (int i = 0; i < fields.length; i++) {
			fields[i].setAccessible(true);
			try {
				cel.put(fields[i].getName(), fields[i].get(clas));
			}
			catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			catch (IllegalAccessException e) {
				e.printStackTrace();
			}
		}
		return cel.toString();
	}

	public String ajaxPaserArray(List<Object> value)
	{
		com.dreamsecurity.sso.lib.jsn.JSONObject jobj = new JSONObject();
		com.dreamsecurity.sso.lib.jsn.JSONObject cel = new JSONObject();
		com.dreamsecurity.sso.lib.jsn.JSONArray cell = new JSONArray();

		for (int j = 0; j < value.size(); j++) {
			Object clas = value.get(j);
			Field[] fields = clas.getClass().getDeclaredFields();
			for (int i = 0; i < fields.length; i++) {
				fields[i].setAccessible(true);
				try {
					cel.put(fields[i].getName(), fields[i].get(clas));

				}
				catch (IllegalArgumentException e) {
					// FIXME Auto-generated catch block
					e.printStackTrace();
				}
				catch (IllegalAccessException e) {
					// FIXME Auto-generated catch block
					e.printStackTrace();
				}
			}
			cell.add(cel);
		}
		return cell.toString();
	}

	public static String ajaxPaserArray(List<Object> value, List<String> code)
	{
		JSONObject cel = new JSONObject();
		JSONArray cell = new JSONArray();
		JSONObject codeCell;
		JSONArray objCell;
		JSONObject idobj;
		JSONArray idArr;

		for (int j = 0; j < value.size(); j++) {
			codeCell = new JSONObject();
			objCell = new JSONArray();
			idobj = new JSONObject();
			idArr = new JSONArray();
			List clas = (List) value.get(j);
			for (int k = 0; k < clas.size(); k++) {
				Object cla = clas.get(k);
				cel.put((String) "id", cla);
				objCell.add(cel);
			}
			codeCell.put((String) "code", objCell);
			idobj.put((String) "codeid", code.get(j));
			idArr.add(codeCell);
			idArr.add(idobj);
			cell.add(idArr);
		}

		return cell.toString();
	}

	public static String StateTreeJson(List<Object> node)
	{
		JSONObject jobj = new JSONObject();
		JSONObject cel = new JSONObject();
		JSONObject celsub = null;
		JSONArray cell = new JSONArray();

		for (int j = 0; j < node.size(); j++) {
			Object clas = node.get(j);
			Field[] fields = clas.getClass().getDeclaredFields();
			for (int i = 0; i < fields.length; i++) {
				fields[i].setAccessible(true);

				try {
					celsub = new JSONObject();

					if ("data".equals(fields[i].getName())) {
						cel.put(fields[i].getName(), fields[i].get(clas));
						continue;
					}
					if ("metadata".equals(fields[i].getName())) {
						cel.put(fields[i].getName(), (String) "{  \"id\" : " + "\" " + fields[i].get(clas) + " \" }");

						// cel.put(fields[i].getName(), celsub.put("id",fields[i].get(clas)));
					}
				}
				catch (IllegalArgumentException e) {
					// FIXME Auto-generated catch block
					e.printStackTrace();
				}
				catch (IllegalAccessException e) {
					// FIXME Auto-generated catch block
					e.printStackTrace();
				}

			}

			cell.add(cel);
		}

		return cell.toString();
	}

	public static String TreeJson(List<Object> node)
	{
		JSONObject jobj = new JSONObject();
		JSONObject cel = new JSONObject();
		JSONObject metaObj = null;
		JSONArray cell = new JSONArray();
		JSONArray meta = new JSONArray();
		for (int j = 0; j < node.size(); j++) {
			Object clas = node.get(j);
			Field[] fields = clas.getClass().getDeclaredFields();
			metaObj = new JSONObject();
			for (int i = 0; i < fields.length; i++) {
				fields[i].setAccessible(true);
				try {
					if ("metadata".equals(fields[i].getName())) {
						metaObj.put((Object) "id", fields[i].get(clas));
						continue;
					}
					if ("data".equals(fields[i].getName())) {
						cel.put(fields[i].getName(), fields[i].get(clas));
						continue;
					}
					if ("metadata2".equals(fields[i].getName())) {
						metaObj.put((Object) "id2", fields[i].get(clas));
						continue;
					}
					if ("state".equals(fields[i].getName())) {
						cel.put(fields[i].getName(), fields[i].get(clas));
					}
					cel.put((Object) "metadata", metaObj);
					// cel.put(fields[i].getName(), celsub.put("id",fields[i].get(clas)));
				}
				catch (IllegalArgumentException e) {
					// FIXME Auto-generated catch block
					e.printStackTrace();
				}
				catch (IllegalAccessException e) {
					// FIXME Auto-generated catch block
					e.printStackTrace();
				}

			}
			cell.add(cel);
		}

		return cell.toString();

	}

	public String jqgridAjaxPaser(List<String> key, List<Object> objList, String Count)
	{
		JSONObject jobj = new JSONObject();
		JSONArray cell = new JSONArray();
		JSONObject obj = new JSONObject();
		for (int j = 0; j < objList.size(); j++) {
			for (int i = 0; i < key.size(); i++) {
				Object clas = objList.get(j);
				Field[] fields = objList.get(j).getClass().getDeclaredFields();
				for (int f = 0; f < fields.length; f++) {
					fields[f].setAccessible(true);
					try {
						if (key.get(i).equals(fields[f].getName())) {
							obj.put(key.get(i), fields[f].get(clas));
						}
					}
					catch (IllegalArgumentException e) {
						// FIXME Auto-generated catch block
						e.printStackTrace();
					}
					catch (IllegalAccessException e) {
						// FIXME Auto-generated catch block
						e.printStackTrace();
					}

				}
			}
			cell.add(obj);
		}

		jobj.put("total", Count);
		jobj.put("rows", cell);

		return jobj.toString();
	}

	public static String jqgridPaser(List<String> key, List<Object> objList)
	{
		JSONObject jobj = new JSONObject();
		JSONArray cell = new JSONArray();

		for (int j = 0; j < objList.size(); j++) {
			JSONObject obj = new JSONObject();

			for (int i = 0; i < key.size(); i++) {
				Object clas = objList.get(j);
				Field[] fields = objList.get(j).getClass().getDeclaredFields();

				if (clas instanceof Map) {
					Map ObjMap = (Map) clas;
					for (int f = 0; f < objList.size(); f++) {
						try {
							String emptyChk = (String) ObjMap.get((String) key.get(i));
							if ((emptyChk != null) && !(emptyChk.equals(""))) {
								obj.put(key.get(i), ObjMap.get((String) key.get(i)));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
				else {
					for (int f = 0; f < fields.length; f++) {
						fields[f].setAccessible(true);
						try {
							if (key.get(i).equals(fields[f].getName())) {
								obj.put(key.get(i), fields[f].get(clas));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
						catch (IllegalAccessException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			}

			cell.add(obj);
		}

		jobj.put("total", objList.size());
		jobj.put("records", objList.size());
		jobj.put("rows", cell);

		return jobj.toString();
	}

	public static String jqgridPaser(List<String> key, List<Object> objList, int totalCnt)
	{
		JSONObject jobj = new JSONObject();
		JSONArray cell = new JSONArray();

		for (int j = 0; j < objList.size(); j++) {
			JSONObject obj = new JSONObject();

			for (int i = 0; i < key.size(); i++) {
				Object clas = objList.get(j);
				Field[] fields = objList.get(j).getClass().getDeclaredFields();

				if (clas instanceof Map) {
					Map ObjMap = (Map) clas;
					for (int f = 0; f < objList.size(); f++) {
						try {
							String emptyChk = (String) ObjMap.get((String) key.get(i));
							if ((emptyChk != null) && !(emptyChk.equals(""))) {
								obj.put(key.get(i), ObjMap.get((String) key.get(i)));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
				else {
					for (int f = 0; f < fields.length; f++) {
						fields[f].setAccessible(true);
						try {
							if (key.get(i).equals(fields[f].getName())) {
								obj.put(key.get(i), fields[f].get(clas));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
						catch (IllegalAccessException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			}

			cell.add(obj);
		}

		jobj.put("total", totalCnt);
		jobj.put("records", objList.size());
		jobj.put("rows", cell);

		return jobj.toString();
	}

	public static String jqgridPaser(List<String> key, List<Object> objList, int totalCnt, int pageNo)
	{
		JSONObject jobj = new JSONObject();
		JSONArray cell = new JSONArray();

		for (int j = 0; j < objList.size(); j++) {
			JSONObject obj = new JSONObject();

			for (int i = 0; i < key.size(); i++) {
				Object clas = objList.get(j);
				Field[] fields = objList.get(j).getClass().getDeclaredFields();

				if (clas instanceof Map) {
					Map ObjMap = (Map) clas;
					for (int f = 0; f < objList.size(); f++) {
						try {
							String emptyChk = (String) ObjMap.get((String) key.get(i));
							if ((emptyChk != null) && !(emptyChk.equals(""))) {
								obj.put(key.get(i), ObjMap.get((String) key.get(i)));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
				else {
					for (int f = 0; f < fields.length; f++) {
						fields[f].setAccessible(true);
						try {
							if (key.get(i).equals(fields[f].getName())) {
								obj.put(key.get(i), fields[f].get(clas));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
						catch (IllegalAccessException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			}

			cell.add(obj);
		}

		jobj.put("page", pageNo);
		jobj.put("total", totalCnt);
		jobj.put("records", objList.size());
		jobj.put("rows", cell);

		return jobj.toString();
	}

	public static String apiPaser(List<String> key, List<Object> objList, int status)
	{
		JSONObject jobj = new JSONObject();
		JSONArray cell = new JSONArray();
		JSONObject obj = new JSONObject();

		for (int j = 0; j < objList.size(); j++) {
			for (int i = 0; i < key.size(); i++) {
				Object clas = objList.get(j);
				Field[] fields = objList.get(j).getClass().getDeclaredFields();
				if (clas instanceof Map) {
					Map ObjMap = (Map) clas;
					for (int f = 0; f < objList.size(); f++) {
						try {
							String emptyChk = (String) ObjMap.get((String) key.get(i));
							if ((emptyChk != null) && !(emptyChk.equals(""))) {
								obj.put(key.get(i), ObjMap.get((String) key.get(i)));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
				else {
					for (int f = 0; f < fields.length; f++) {
						fields[f].setAccessible(true);
						try {
							if (key.get(i).equals(fields[f].getName())) {
								obj.put(key.get(i), fields[f].get(clas));
							}
						}
						catch (IllegalArgumentException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}
						catch (IllegalAccessException e) {
							// FIXME Auto-generated catch block
							e.printStackTrace();
						}

					}
				}

			}
			cell.add(obj);
		}

		jobj.put("status", status);
		jobj.put("data", cell);

		return jobj.toString();
	}

	public String jqgridDatePaser(List<String> key, List<Object> objList, int total)
	{
		JSONObject jobj = new JSONObject();
		JSONArray cell = new JSONArray();
		JSONObject obj = new JSONObject();
		for (int j = 0; j < objList.size(); j++) {
			for (int i = 0; i < key.size(); i++) {
				Object clas = objList.get(j);
				Field[] fields = objList.get(j).getClass().getDeclaredFields();
				for (int f = 0; f < fields.length; f++) {
					fields[f].setAccessible(true);
					try {
						if (key.get(i).equals(fields[f].getName())) {
							obj.put(key.get(i), fields[f].get(clas));
						}
					}
					catch (IllegalArgumentException e) {
						// FIXME Auto-generated catch block
						e.printStackTrace();
					}
					catch (IllegalAccessException e) {
						// FIXME Auto-generated catch block
						e.printStackTrace();
					}

				}
			}
			cell.add(obj);
		}

		jobj.put("total", objList.size());
		jobj.put("records", objList.size());
		jobj.put("rows", cell);
		jobj.put("rept30date", total);

		return jobj.toString();
	}
}
