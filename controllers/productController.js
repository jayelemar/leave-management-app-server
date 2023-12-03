const asyncHandler = require("express-async-handler")
const Product = require("../models/productModel")
const { fileSizeFormatter } = require("../utils/uploadFile");
const cloudinary = require("cloudinary").v2;

const createProduct = asyncHandler(async (req, res) => {
    const { name, sku, category, quantity, price, description } = req.body

    // Validation
    if( !name || !category || !price || !description ) {
        res.status(400)
        throw new Error("Please full in all fields")
    }
    // Handle Image Upload
    let fileData = {}
    if(req.file) {

        // Save Image to Cloudinary
        let uploadedFile;
        try {
            uploadedFile = await cloudinary.uploader.upload(req.file.path, {folder: "Inventory Mngt App", resource_type: "image"})
        } catch (error) {
            res.status(500)
            throw new Error("Image could not be uploaded")
        }

        fileData = {
            fileName: req.file.originalname,
            filePath: uploadedFile.secure_url,
            fileType: req.file.mimetype,
            fileSize: fileSizeFormatter(req.file.size, 2),    
        }
    }

    // Create Product
    const product = await Product.create({
        user: req.user.id,
        name,
        sku,
        category,
        quantity,
        price,
        description,
        image: fileData,
    })
    res.status(201).json(product)
});

const getProducts = asyncHandler(async (req, res) => {
    const products = await Product
        .find({ user: req.user.id })
        .sort("-createdAt") // sort from latest to oldest
    res.status(200).json(products)
});

const getProduct = asyncHandler(async (req, res) => {
    const product = await Product.findById(req.params.id)
    if (!product) {
        res.status(404)
        throw new Error("Product not found")
    }

    if(product.user.toString() !== req.user.id) {
        res.status(401)
        throw new Error("User not authorized")
    }

    res.status(200).json(product);
});

const deleteProduct = asyncHandler(async (req, res) => {
    const product = await Product.findById(req.params.id)
    if (!product) {
        res.status(404)
        throw new Error("Product not found")
    }
    //Match product to its user 
    if(product.user.toString() !== req.user.id) {
        res.status(401)
        throw new Error("User not authorized")
    }
    await product.deleteOne();
    res.status(200).json({ message: "Product Deleted." })
});

const updateProduct = asyncHandler(async (req, res) => {
    const { name, category, quantity, price, description } = req.body
    const { id } = req.params
    const product = await Product.findById(id)

    // if product does not found
    if (!product) {
        res.status(404)
        throw new Error("Product not found")
    }
    //Match product to its user 
    if(product.user.toString() !== req.user.id) {
        res.status(401)
        throw new Error("User not authorized")
    }


    // Handle Image Upload
    let fileData = {}
    if(req.file) {

        // Save Image to Cloudinary
        let uploadedFile;
        try {
            uploadedFile = await cloudinary.uploader.upload(req.file.path, {folder: "Inventory Mngt App", resource_type: "image"})
        } catch (error) {
            res.status(500)
            throw new Error("Image could not be uploaded")
        }

        fileData = {
            fileName: req.file.originalname,
            filePath: uploadedFile.secure_url,
            fileType: req.file.mimetype,
            fileSize: fileSizeFormatter(req.file.size, 2),    
        }
    }

    // Update Product
    const updatedProduct = await Product.findByIdAndUpdate(
        {_id: id}, 
        {
            name,
            category,
            quantity,
            price,
            description,
            image: Object.keys(fileData).length === 0 ? product?.image : fileData,
        },
        {
            new: true,
            runValidators: true,
        }
    )

    res.status(200).json(updatedProduct)
});


module.exports = {
    createProduct,
    getProducts,
    getProduct,
    deleteProduct,
    updateProduct,
}

