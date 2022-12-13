GNUPG libksba 1.6.1 overflow

<pre>
static gpg_error_t
parse_encrypted_content_info (ksba_reader_t reader,
                              unsigned long *r_len, int *r_ndef,
                              char **r_cont_oid, char **r_algo_oid,
                              char **r_algo_parm, size_t *r_algo_parmlen,
                              int *r_algo_parmtype,
                              int *has_content)
{
...
[1]  err = _ksba_ber_read_tl (reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return gpg_error (GPG_ERR_INV_CMS_OBJ);
  if (!content_ndef)
    {
      if (content_len < ti.nhdr)
        return gpg_error (GPG_ERR_BAD_BER); /* triplet header larger that sequence */
      content_len -= ti.nhdr;
      if (content_len < ti.length)
        return gpg_error (GPG_ERR_BAD_BER); /* triplet larger that sequence */
      content_len -= ti.length;
    }
[2]  if (ti.nhdr + ti.length >= DIM(tmpbuf))
    return gpg_error (GPG_ERR_TOO_LARGE);
  memcpy (tmpbuf, ti.buf, ti.nhdr);
[3]  err = read_buffer (reader, tmpbuf+ti.nhdr, ti.length);
</pre>

_ksba_ber_read_tl() does not verify ti.length, we  can set it to any value.

If we set it to (unsigned long)-1 check on line #2 will be bypassed.

As a result we have overflow on line #3.

How to test:
<pre>
1. build libksba with asan
2. edit tests/t-cms-parser.c to open 1.cms file
3. run tests/t-cms-parser

OR
$ gpgsm --verify 1.cms
</pre>
