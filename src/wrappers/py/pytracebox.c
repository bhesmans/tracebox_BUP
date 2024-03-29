#include <arpa/inet.h>
#include <Python.h>

#include "libtracebox/dnet_compat.h"
#include "libtracebox/tracebox.h"
#include "libtracebox/packet.h"

#define min(a,b)	(a > b ? b : a)

staticforward PyTypeObject ProbeResult_Type;

typedef struct {
	PyObject_HEAD
	int		ttl;
	tbox_res_t	res;
} ProbeResult;

static void ProbeResult_dealloc(PyObject *self)
{
	PyMem_DEL(self);
}

static PyObject *ProbeResult_router(PyObject *self)
{
	ProbeResult *probe = (ProbeResult *) self;
	struct in_addr addr = { .s_addr = probe->res.from, };
	return PyString_FromString(inet_ntoa(addr));
}

static PyObject *ProbeResult_probe(PyObject *self)
{
	ProbeResult *probe = (ProbeResult *) self;
	return PyString_FromStringAndSize(probe->res.probe, probe->res.probe_len);
}

static PyObject *ProbeResult_reply(PyObject *self)
{
	ProbeResult *probe = (ProbeResult *) self;
	return PyString_FromStringAndSize(probe->res.reply, probe->res.reply_len);
}

#define ProbeResult_Macro(field, value, chg) \
static PyObject *ProbeResult_ ## field (PyObject *self) \
{ \
	ProbeResult *probe = (ProbeResult *) self; \
	if (probe->res.chg & (value)) \
		Py_RETURN_TRUE; \
	else \
		Py_RETURN_FALSE; \
}

#define ProbeResult_has(field, value) \
	ProbeResult_Macro(field##_changed, value, chg_prev)

#define ProbeResult_has_p(field, value, chg) \
	ProbeResult_Macro(field##_changed, value,  chg)

#define ProbeResult_Fct(field) \
	{ #field, (PyCFunction)ProbeResult_##field, METH_NOARGS, NULL }
#define ProbeResult_Fct_has(field) ProbeResult_Fct(field##_changed)


ProbeResult_has(ip_hlen,	IP_HLEN);
ProbeResult_has(dscp,		IP_DSCP);
ProbeResult_has(ecn,		IP_ECN);
ProbeResult_has(ip_tlen,	IP_TLEN_INCR | IP_TLEN_DECR);
ProbeResult_has(ip_id,		IP_ID);
ProbeResult_has(frag,		IP_FRAG);
ProbeResult_has(source_addr,	IP_SADDR);
ProbeResult_has(source_port,	L4_SPORT);
ProbeResult_has(tcp_seq,	TCP_SEQ);
ProbeResult_has_p(tcp_hlen,	TCP_DOFF, chg_start);
ProbeResult_has_p(tcp_rwin,	TCP_WIN, chg_start);
ProbeResult_has_p(tcp_flags,	TCP_FLAGS, chg_start);
ProbeResult_has_p(tcp_opt,	TCP_OPT, chg_start);
ProbeResult_has(udp_len,	UDP_LEN);
ProbeResult_has(udp_csum,	UDP_CHKSUM);
ProbeResult_has_p(payload,	PAYLOAD, chg_start);

ProbeResult_Macro(changed,	(uint32_t)-1,	chg_prev);
ProbeResult_Macro(is_full_reply,FULL_REPLY,	chg_start);
ProbeResult_Macro(is_srv_reply,	SRV_REPLY,	chg_start);

static PyMethodDef ProbeResultMethods[] = {
	{ "router", (PyCFunction)ProbeResult_router, METH_NOARGS, NULL },
	{ "probe", (PyCFunction)ProbeResult_probe, METH_NOARGS, NULL },
	{ "reply", (PyCFunction)ProbeResult_reply, METH_NOARGS, NULL },
	ProbeResult_Fct_has(ip_hlen),
	ProbeResult_Fct_has(dscp),
	ProbeResult_Fct_has(ecn),
	ProbeResult_Fct_has(ip_tlen),
	ProbeResult_Fct_has(ip_id),
	ProbeResult_Fct_has(frag),
	ProbeResult_Fct_has(source_addr),
	ProbeResult_Fct_has(source_port),
	ProbeResult_Fct_has(tcp_seq),
	ProbeResult_Fct_has(tcp_hlen),
	ProbeResult_Fct_has(tcp_rwin),
	ProbeResult_Fct_has(tcp_flags),
	ProbeResult_Fct_has(tcp_opt),
	ProbeResult_Fct_has(udp_len),
	ProbeResult_Fct_has(udp_csum),
	ProbeResult_Fct_has(payload),

	ProbeResult_Fct(changed),
	ProbeResult_Fct(is_full_reply),
	ProbeResult_Fct(is_srv_reply),
	{ NULL, NULL, 0, NULL },
};

static PyObject *ProbeResult_getattr(PyObject *self, char *name)
{
	return Py_FindMethod(ProbeResultMethods, self, name);
}

static PyTypeObject ProbeResult_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/*ob_size*/
	"tracebox.probe",			/*tp_name*/
	sizeof(ProbeResult),			/*tp_basicsize*/
	0,					/*tp_itemsize*/
	/* methods */
	(destructor) ProbeResult_dealloc,	/*tp_dealloc*/
	0,					/*print*/
	(getattrfunc) ProbeResult_getattr,	/*tp_getattr*/
	0,					/*tp_setattr*/
	0,					/*tp_compare*/ 
	0,					/*tp_repr*/
	0,					/*tp_as_number*/
	0,					/*tp_as_sequence*/
	0,					/*tp_as_mapping*/
	0,					/*tp_hash*/
	0,					/*tp_call*/
	0,					/*tp_str*/
	0,					/*tp_getattro*/
	0,					/*tp_setattro*/
	0,					/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,			/*tp_flags*/
	"Probe result",				/*tp_doc*/
};

static PyObject *dump_func = NULL;
static PyObject *cb_func = NULL;

static PyObject *build_tbox_res(int ttl, const tbox_res_t *res)
{
	if (res->sent_probes && res->recv_probes) {
		ProbeResult *probe = PyObject_NEW(ProbeResult, &ProbeResult_Type);
		probe->ttl = ttl;
		memcpy(&probe->res, res, sizeof(probe->res));
		return (PyObject *)probe;
	} else {
		Py_INCREF(Py_None);
		return Py_None;
	}
}

static PyObject *build_return(const tbox_conf_t *tbox, const tbox_res_t *res)
{
	int i;
	PyObject *dict = PyDict_New();

	for (i = tbox->min_ttl; i <= tbox->max_ttl; ++i) {
		PyObject *key = Py_BuildValue("i", i);
		PyObject *value = build_tbox_res(i, &res[i]);
		PyDict_SetItem(dict, key, value);
	}
	return dict;
}

static void stub_dump(const uint8_t const *pkt, size_t len)
{
	if (!dump_func)
		return;

	PyObject *pkt_dump = Py_BuildValue("(s#)", pkt, len);
	PyEval_CallObject(dump_func, pkt_dump);
}

static int stub_cb(int ttl, tbox_res_t *res)
{
	if (!cb_func)
		return 0;

	PyObject *pyres = build_tbox_res(ttl, res);
	PyObject *arg = Py_BuildValue("(iO)", ttl, pyres);
	PyEval_CallObject(cb_func, arg);

	return 0;
}

static PyObject *tracebox_trace(PyObject *self, PyObject *args, PyObject *kwds)
{
	char *probe;
	int probe_len;
	tbox_conf_t tbox = TBOX_DEFAULT;
	tbox_res_t res[TBOX_HARD_TTL+1];
	int ret, test1, test2;
	PyObject *dump = NULL;
	PyObject *cb = NULL;
	char *kwlist[] = { "probe", "iface", "min_ttl", "max_ttl", "nprobes",
			   "timeout", "noreply", "dump", "callback", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#|siiiiiOO", kwlist,
					 &probe, &probe_len, &tbox.iface,
					 &tbox.min_ttl, &tbox.max_ttl,
					 &tbox.nprobes, &tbox.probe_timeo,
					 &tbox.noreply, &dump, &cb))
		return NULL;

	if (dump && !PyCallable_Check(dump))
		PyErr_SetString(PyExc_TypeError, "dump must be a callable object!");
	dump_func = dump;

	if (cb && !PyCallable_Check(cb))
		PyErr_SetString(PyExc_TypeError, "callback must be a callable object!");
	cb_func = cb;

	memset(res, 0, sizeof(res));
	ret = tracebox(probe, probe_len, res, 9, TBOX_IFACE, tbox.iface,
		       TBOX_MIN_TTL, tbox.min_ttl, TBOX_MAX_TTL, tbox.max_ttl,
		       TBOX_NPROBES, tbox.nprobes, TBOX_PROBE_TIMEO,
		       tbox.probe_timeo, TBOX_NOREPLY, tbox.noreply,
		       TBOX_SENT_CB, stub_dump, TBOX_RECV_CB, stub_dump,
		       TBOX_CB, stub_cb);
	return build_return(&tbox, res);
}

static PyObject *tracebox_replay(PyObject *self, PyObject *args, PyObject *kwds)
{
	uint8_t *probe, *reply, *prev = NULL;
	int ttl, probe_len, reply_len, prev_len;
	tbox_res_t res;
	char *kwlist[] = { "probe", "reply", "prev_reply", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "is#s#|s#", kwlist, &ttl,
					 &probe, &probe_len, &reply, &reply_len,
					 &prev, &prev_len))
		return NULL;

	res.sent_probes = res.recv_probes = 1;
	res.probe_len = min(probe_len, TBOX_PKT_SIZE);
	memcpy(res.probe, probe, res.probe_len);

	reply = tbox_trim_pkt(reply, (size_t *)&reply_len, &res.from);
	res.reply_len = min(reply_len, TBOX_PKT_SIZE);
	memcpy(res.reply, reply, res.reply_len);

	res.chg_start = tbox_diff_packet(probe, res.probe_len, reply, res.reply_len);
	res.chg_start |= (res.probe_len <= res.reply_len ? FULL_REPLY : 0);
	res.chg_prev = res.chg_start;
	if (prev) {
		prev = tbox_trim_pkt(prev, (size_t *)&prev_len, NULL);
		res.chg_prev = tbox_diff_packet(prev, prev_len, reply, res.reply_len);
	}

	return build_tbox_res(ttl, &res);
}

static PyMethodDef TraceboxMethods[] = {
	{ "trace", (PyCFunction)tracebox_trace, METH_VARARGS|METH_KEYWORDS, NULL },
	{ "replay", (PyCFunction)tracebox_replay, METH_VARARGS|METH_KEYWORDS, NULL },
	{ NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC init_tracebox()
{
	Py_InitModule("_tracebox", TraceboxMethods);
}