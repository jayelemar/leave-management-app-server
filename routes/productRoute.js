const express = require("express");
const Product = require("../models/productModel")
const { createProduct, getProducts, getProduct, deleteProduct, updateProduct } = require("../controllers/productController");
const protect = require("../middleware/authMiddleware");
const { upload } = require("../utils/uploadFile");

const router = express.Router();

router.post("/", protect, upload.single("image"), createProduct )
router.get("/", protect, getProducts)
router.get("/:id", protect, getProduct)
router.delete("/:id", protect, deleteProduct)
router.patch("/:id", protect, upload.single("image"), updateProduct)

module.exports = router