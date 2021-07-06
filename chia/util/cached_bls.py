import functools
import hashlib

from blspy import AugSchemeMPL, G1Element, G2Element, GTElement
from chia.util.lru_cache import LRUCache


# TODO: add heuristic to fall back to AugSchemeMPL.aggregate_verify() when syncing
def get_pairings(cache, pks, msgs):
    for pk, msg in zip(pks, msgs):
        aug_msg = bytes(pk) + msg
        h = hashlib.sha256(aug_msg).digest()
        pairing = cache.get(h)
        if pairing is None:
            aug_hash = AugSchemeMPL.g2_from_message(aug_msg)
            pairing = pk.pair(aug_hash)
            cache.put(h, pairing)

        yield pairing


def cached_aggregate_verify(cache: LRUCache, pks, msgs, sig):
    if len(pks) == 0 and sig == G2Element():
        return True
    pairings_prod = functools.reduce(GTElement.__mul__, get_pairings(cache, pks, msgs))
    return pairings_prod == sig.pair(G1Element.generator())


local_cache = LRUCache(10000)


def aggregate_verify_noc(pks, msgs, sig):
    return AugSchemeMPL.aggregate_verify(pks, msgs, sig)


def aggregate_verify(pks, msgs, sig):
    return cached_aggregate_verify(local_cache, pks, msgs, sig)
