"""CapaGap: evidence-aware comparison of static and dynamic capa results."""

__version__ = "0.2.1"

from capagap.analysis import compare_documents
from capagap.io import load_document
from capagap.matrix import compare_matrix

__all__ = ["compare_documents", "compare_matrix", "load_document"]
